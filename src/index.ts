// collection-file-encrypted.ts
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as https from 'https';
//@ts-ignore
import * as _ from 'underscore';
import Ajv from 'ajv';
import { Shamir } from './shamir';
import { EncryptedData, Encryption } from './encryption';

export interface ICollectionOptions {
    numShares?: number;
    threshold?: number;
    persistent?: boolean;
    filePath?: string;
    password?: string;
    autoSaveInterval?: number;
    auditLogPath?: string;
    port?: number;
    tlsCertPath?: string;
    tlsKeyPath?: string;
}

type SystemKey = { type: string };

export class Collection<T extends object = any> {
    private data: Array<{
        key: Partial<T> | SystemKey;
        value: EncryptedData;
        meta: { readonly: boolean };
        created: number;
        deleted: boolean;
        version: number
    }> = [];
    private numShares: number;
    private threshold: number;
    private persistent: boolean;
    private autoSaveInterval: number;
    private filePath: string;
    private auditLogPath: string;
    private masterKey: Buffer | null = null;
    private sek: Buffer | null = null;
    private locked: boolean = true;
    private shares: Uint8Array[] = [];
    private _saveTimer: NodeJS.Timeout | null = null;
    private _encryptedVault: { iv: string; tag: string; ciphertext: string; hmac: string } | null = null;
    private passwordHash: string | null = null;
    private server: https.Server | null = null;
    private port: number;
    private tlsCert: string | null = null;
    private tlsKey: string | null = null;
    private ajv: Ajv;
    private keySchemaValidator: any = null;
    private valueSchemaValidator: any = null;

    static collection<T extends object = any>(name: string, schema: { key?: object; value?: object } = {}, options: ICollectionOptions = {}) {
        return new Collection<T>(name, schema, options);
    }

    constructor(
        private collectionName: string,
        private schema: { key?: object; value?: object },
        options: ICollectionOptions = {}
    ) {
        this.numShares = options.numShares ?? 5;
        this.threshold = options.threshold ?? 3;
        this.persistent = options.persistent ?? false;
        this.autoSaveInterval = options.autoSaveInterval ?? 1000;
        this.port = options.port ?? 3000;

        if (options.tlsCertPath) this.tlsCert = fs.readFileSync(options.tlsCertPath, 'utf8');
        if (options.tlsKeyPath) this.tlsKey = fs.readFileSync(options.tlsKeyPath, 'utf8');

        if (this.numShares < this.threshold) throw new Error('numShares must be >= threshold');
        if (this.threshold < 1) throw new Error('threshold must be >= 1');

        if (options.password) {
            this.passwordHash = crypto.createHash('sha256').update(options.password).digest('hex');
        }

        if (this.persistent) {
            if (options.filePath) {
                this.filePath = path.resolve(options.filePath);
            } else {
                const appDir = path.join(
                    os.homedir(),
                    process.platform === 'win32' ? 'AppData\\Local\\CipherDB' :
                        process.platform === 'darwin' ? 'Library/Application Support/CipherDB' :
                            '.CipherDB'
                );
                if (!fs.existsSync(appDir)) fs.mkdirSync(appDir, { recursive: true });
                this.filePath = path.join(appDir, 'vault.json');
            }
            this.auditLogPath = options.auditLogPath ?? path.join(path.dirname(this.filePath), 'audit.log');

            if (fs.existsSync(this.filePath)) {
                this._encryptedVault = JSON.parse(fs.readFileSync(this.filePath, 'utf-8'));
            }
        } else {
            this.filePath = '';
            this.auditLogPath = '';
        }

        if (this.persistent) {
            const flushOnExit = () => {
                console.log('Flushing vault before exit...');
                this.flush();
            };
            process.on('SIGINT', flushOnExit);
            process.on('SIGTERM', flushOnExit);
            process.on('uncaughtException', (err) => {
                console.error('Uncaught exception:', err);
                flushOnExit();
                process.exit(1);
            });
        }

        this.ajv = new Ajv({ allErrors: true });
        if (this.schema.key) {
            this.keySchemaValidator = this.ajv.compile(this.schema.key);
        }
        if (this.schema.value) {
            this.valueSchemaValidator = this.ajv.compile(this.schema.value);
        }
    }

    async init(): Promise<string[]> {
        const masterKey = crypto.randomBytes(32);
        const sek = crypto.randomBytes(32);
        if (!masterKey || !sek) throw new Error('Failed to generate keys');
        this.masterKey = masterKey;
        this.sek = sek;
        console.log('Initialized masterKey and sek:', {
            masterKeyLength: this.masterKey.length,
            sekLength: this.sek.length
        });

        this.shares = await Shamir.split(new Uint8Array(masterKey), this.numShares, this.threshold);
        const encryptedSek = Encryption.encrypt(sek.toString('hex'), masterKey);
        this.data.push({
            key: { type: 'ENCRYPTED_SEK' } as SystemKey,
            value: encryptedSek,
            meta: { readonly: true },
            created: Date.now(),
            deleted: false,
            version: 1
        });

        if (this.persistent) this._scheduleSave();
        this.locked = true;
        console.log('Collection initialized and locked. Distribute these shares:', this.shares.map(s => Buffer.from(s).toString('hex')));
        this.logOperation('init', { timestamp: Date.now() });
        return this.shares.map(s => Buffer.from(s).toString('hex'));
    }

    async unlock(providedShares: string[], password?: string): Promise<void> {
        if (this.passwordHash && crypto.createHash('sha256').update(password ?? '').digest('hex') !== this.passwordHash) {
            throw new Error('Invalid password');
        }
        if (providedShares.length < this.threshold) {
            throw new Error(`Need at least ${this.threshold} shares to unlock`);
        }

        const sharesUint8 = providedShares.map(s => Uint8Array.from(Buffer.from(s, 'hex')));
        const masterKey = Buffer.from(await Shamir.combine(sharesUint8));
        if (!masterKey) throw new Error('Failed to reconstruct master key');
        this.masterKey = masterKey;

        if (this._encryptedVault) {
            const { iv, tag, ciphertext, hmac } = this._encryptedVault;
            const decryptedJson = Encryption.decrypt({ iv, tag, ciphertext }, masterKey);
            const computedHmac = crypto.createHmac('sha256', masterKey).update(decryptedJson).digest('hex');
            if (hmac !== computedHmac) throw new Error('Vault tampered!');
            this.data = JSON.parse(decryptedJson);
        }

        const encSek = this.data.find(d => 'type' in d.key && d.key.type === 'ENCRYPTED_SEK')?.value;
        if (!encSek) throw new Error('ENCRYPTED_SEK not found');
        const sekHex = Encryption.decrypt(encSek, masterKey);
        const sek = Buffer.from(sekHex, 'hex');
        if (!sek) throw new Error('Failed to load SEK');
        this.sek = sek;
        console.log('Unlocked with masterKey and sek:', {
            masterKeyLength: masterKey.length,
            sekLength: sek.length
        });

        this.locked = false;
        console.log('Collection unlocked. SEK loaded in memory.');
        this.logOperation('unlock', { timestamp: Date.now() });
    }

    lock(): void {
        this.masterKey = null;
        this.sek = null;
        this.locked = true;
        console.log('Collection locked.');
        this.logOperation('lock', { timestamp: Date.now() });
    }

    async rotateMasterKey(): Promise<string[]> {
        if (this.locked) throw new Error('Collection is locked! Cannot rotate.');
        if (!this.masterKey || !this.sek) throw new Error('Master key or SEK not available');
        const oldMasterKey: Buffer = this.masterKey;
        const sek: Buffer = this.sek;
        const newMasterKey = crypto.randomBytes(32);
        if (!newMasterKey) throw new Error('Failed to generate new master key');
        this.masterKey = newMasterKey;

        this.shares = await Shamir.split(new Uint8Array(newMasterKey), this.numShares, this.threshold);
        this.data = this.data.map(item => {
            if ('type' in item.key && item.key.type === 'ENCRYPTED_SEK') {
                const decryptedSek = Encryption.decrypt(item.value, oldMasterKey);
                return {
                    ...item,
                    value: Encryption.encrypt(decryptedSek, newMasterKey)
                };
            }
            return item;
        });

        this.saveToFile();
        this.logOperation('rotateMasterKey', { timestamp: Date.now() });
        return this.shares.map(s => Buffer.from(s).toString('hex'));
    }

    insert(key: Partial<T>, value: any, meta: { readonly: boolean } = { readonly: false }, version: number = Date.now()): void {
        if (this.locked) throw new Error('Collection is locked! Cannot insert.');
        if (!key || typeof key !== 'object') throw new Error('Key must be a non-empty object');
        if (!value) throw new Error('Value must be provided');
        if (!this.sek) throw new Error('SEK not available');
        const sek: Buffer = this.sek;

        if (this.keySchemaValidator && !this.keySchemaValidator(key)) {
            throw new Error(`Key validation failed: ${JSON.stringify(this.keySchemaValidator.errors)}`);
        }
        if (this.valueSchemaValidator && !this.valueSchemaValidator(value)) {
            throw new Error(`Value validation failed: ${JSON.stringify(this.valueSchemaValidator.errors)}`);
        }

        const item = {
            key,
            value: Encryption.encrypt(JSON.stringify(value), sek),
            meta,
            created: Date.now(),
            deleted: false,
            version
        };
        this.data.push(item);

        if (this.persistent) this._scheduleSave();
        console.log(`Inserted document with key: ${JSON.stringify(key)}, version: ${version}`);
        this.logOperation('insert', { key: JSON.stringify(key), version, timestamp: Date.now() });
    }

    find(query: Partial<T> = {}): Array<{ key: Partial<T> | SystemKey; value: any; meta: { readonly: boolean }; created: number; version: number }> {
        if (this.locked) throw new Error('Collection is locked! Cannot find.');
        if (!this.sek) throw new Error('SEK not available');
        const sek: Buffer = this.sek;

        const results = _.where(this.data, { deleted: false, key: query });
        return results.map((item:any) => ({
            key: item.key,
            value: JSON.parse(Encryption.decrypt(item.value, sek)),
            meta: item.meta,
            created: item.created,
            version: item.version
        }));
    }

    findOne(query: Partial<T> = {}): { key: Partial<T> | SystemKey; value: any; meta: { readonly: boolean }; created: number; version: number } | null {
        if (this.locked) throw new Error('Collection is locked! Cannot findOne.');
        if (!this.sek) throw new Error('SEK not available');
        const sek: Buffer = this.sek;

        const item = _.findWhere(this.data, { deleted: false, key: query });
        if (!item) return null;
        return {
            key: item.key,
            value: JSON.parse(Encryption.decrypt(item.value, sek)),
            meta: item.meta,
            created: item.created,
            version: item.version
        };
    }

    update(query: Partial<T>, update: Partial<any>, version?: number): number {
        if (this.locked) throw new Error('Collection is locked! Cannot update.');
        if (!this.sek) throw new Error('SEK not available');
        const sek: Buffer = this.sek;

        if (this.valueSchemaValidator && !this.valueSchemaValidator(update)) {
            throw new Error(`Update value validation failed: ${JSON.stringify(this.valueSchemaValidator.errors)}`);
        }

        let count = 0;
        this.data = this.data.map(item => {
            if (item.deleted || !_.isMatch(item.key, query)) return item;
            if (version && item.version !== version) return item;
            if (item.meta.readonly) return item;
            count++;
            return {
                ...item,
                value: Encryption.encrypt(JSON.stringify(update), sek),
                version: version ?? Date.now()
            };
        });
        if (count > 0 && this.persistent) this._scheduleSave();
        this.logOperation('update', { query: JSON.stringify(query), version, timestamp: Date.now() });
        return count;
    }

    delete(query: Partial<T>, version?: number): number {
        if (this.locked) throw new Error('Collection is locked! Cannot delete.');
        if (!this.sek) throw new Error('SEK not available');
        const sek: Buffer = this.sek;

        let count = 0;
        this.data = this.data.map(item => {
            if (item.deleted || !_.isMatch(item.key, query)) return item;
            if (version && item.version !== version) return item;
            if (item.meta.readonly) return item;
            count++;
            return { ...item, deleted: true, value: Encryption.encrypt('{}', sek) };
        });
        if (count > 0 && this.persistent) this._scheduleSave();
        this.logOperation('delete', { query: JSON.stringify(query), version, timestamp: Date.now() });
        return count;
    }

    count(query: Partial<T> = {}): number {
        if (this.locked) throw new Error('Collection is locked! Cannot count.');
        return this.find(query).length;
    }

    list(): Array<{ key: Partial<T> | SystemKey; value: any; meta: { readonly: boolean }; type: string; created: number; version: number }> {
        if (this.locked) throw new Error('Collection is locked! Cannot list.');
        if (!this.sek) throw new Error('SEK not available');
        const sek: Buffer = this.sek;

        return this.data
            .filter(item => !item.deleted && !('type' in item.key && item.key.type === 'ENCRYPTED_SEK'))
            .map(item => {
                const decrypted = JSON.parse(Encryption.decrypt(item.value, sek));
                return {
                    key: item.key,
                    value: item.meta.readonly ? 'read-only' : decrypted,
                    meta: item.meta,
                    type: typeof decrypted,
                    created: item.created,
                    version: item.version
                };
            });
    }

    saveShares(outputDir: string): void {
        if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
        this.shares.forEach((share, i) => {
            const filePath = path.join(outputDir, `share_${i + 1}.txt`);
            fs.writeFileSync(filePath, Buffer.from(share).toString('hex'), 'utf8');
        });
        console.log(`Shares saved securely to ${outputDir}`);
    }

    private _scheduleSave(): void {
        if (this._saveTimer) clearTimeout(this._saveTimer);
        this._saveTimer = setTimeout(() => {
            this.saveToFile();
            this._saveTimer = null;
        }, this.autoSaveInterval);
    }

    flush(): void {
        if (!this.persistent) return;
        if (this._saveTimer) {
            clearTimeout(this._saveTimer);
            this._saveTimer = null;
        }
        this.saveToFile();
        console.log('Collection flushed to disk immediately.');
    }

    saveToFile(): void {
        if (!this.masterKey) throw new Error('Cannot save without master key');
        const masterKey: Buffer = this.masterKey;
        const vaultString = JSON.stringify(this.data, null, 2);
        const encryptedVault = Encryption.encrypt(vaultString, masterKey);
        const hmac = crypto.createHmac('sha256', masterKey).update(vaultString).digest('hex');
        const dataToSave = { ...encryptedVault, hmac, passwordHash: this.passwordHash };
        fs.writeFileSync(this.filePath, JSON.stringify(dataToSave), 'utf-8');
        if (process.platform !== 'win32') {
            fs.chmodSync(this.filePath, '600');
        }
    }

    logOperation(operation: string, details: Record<string, any>): void {
        if (!this.auditLogPath) return;
        const timestamp = new Date().toISOString();
        const logEntry = `${timestamp} - ${operation}: ${JSON.stringify(details)}\n`;
        fs.appendFileSync(this.auditLogPath, logEntry, 'utf8');
    }

    backup(backupPath: string): void {
        if (!this.persistent || !fs.existsSync(this.filePath)) throw new Error('No vault to backup');
        fs.copyFileSync(this.filePath, backupPath);
        console.log(`Collection backed up to ${backupPath}`);
        this.logOperation('backup', { path: backupPath, timestamp: Date.now() });
    }

    restore(backupPath: string): void {
        if (!fs.existsSync(backupPath)) throw new Error('Backup file does not exist');
        this._encryptedVault = JSON.parse(fs.readFileSync(backupPath, 'utf-8'));
        console.log(`Collection restored from ${backupPath}`);
        this.logOperation('restore', { path: backupPath, timestamp: Date.now() });
    }
}
``