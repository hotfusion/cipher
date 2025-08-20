// cipher-file-encrypted.ts
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { split, combine } from 'shamir-secret-sharing';
import * as express from 'express';
import * as https from 'https';

class Shamir {
    static async split(secret: Uint8Array, n: number, k: number): Promise<Uint8Array[]> {
        return split(secret, n, k);
    }

    static async combine(shares: Uint8Array[]): Promise<Uint8Array> {
        return combine(shares);
    }
}

interface EncryptedData {
    iv: string;
    tag: string;
    ciphertext: string;
}

class Encryption {
    static encrypt(data: string, key: Buffer): EncryptedData {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const ciphertext = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        return { iv: iv.toString('hex'), tag: tag.toString('hex'), ciphertext: ciphertext.toString('hex') };
    }

    static decrypt({ iv, tag, ciphertext }: EncryptedData, key: Buffer): string {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
        decipher.setAuthTag(Buffer.from(tag, 'hex'));
        return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'hex')), decipher.final()]).toString('utf8');
    }
}

interface CipherOptions {
    numShares?: number;
    threshold?: number;
    persistent?: boolean;
    filePath?: string;
    autoSaveInterval?: number;
    password?: string;
    auditLogPath?: string;
    // For network support
    port?: number;
    tlsCertPath?: string;
    tlsKeyPath?: string;
}

class Cipher {
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
    private secrets: Record<string, EncryptedData> = {};
    private _saveTimer: NodeJS.Timeout | null = null;
    private _encryptedVault: { iv: string; tag: string; ciphertext: string; hmac: string } | null = null;
    private passwordHash: string | null = null;

    // For network support
    private server: https.Server | null = null;
    private port: number;
    private tlsCert: string | null = null;
    private tlsKey: string | null = null;

    constructor(options: CipherOptions = {}) {
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

            // Load encrypted vault if exists
            if (fs.existsSync(this.filePath)) {
                this._encryptedVault = JSON.parse(fs.readFileSync(this.filePath, 'utf-8'));
            }
        } else {
            this.filePath = '';
            this.auditLogPath = '';
        }

        // Crash-safe flush
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
    }

    /**
     * Initializes the Cipher by generating keys and splitting shares.
     */
    async init(): Promise<void> {
        this.masterKey = crypto.randomBytes(32);
        this.sek = crypto.randomBytes(32);

        this.shares = await Shamir.split(this.masterKey, this.numShares, this.threshold);

        // Encrypt SEK with master key
        this.secrets['ENCRYPTED_SEK'] = Encryption.encrypt(this.sek.toString('hex'), this.masterKey);

        if (this.persistent) this._scheduleSave();

        this.locked = true;
        console.log('Cipher initialized and locked. Distribute these shares:', this.shares.map(s => Buffer.from(s).toString('hex')));
        this.logOperation('init', { timestamp: Date.now() });
    }

    /**
     * Saves shares to individual files in the specified directory.
     * @param outputDir Directory to save shares.
     */
    saveShares(outputDir: string): void {
        if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
        this.shares.forEach((share, i) => {
            const filePath = path.join(outputDir, `share_${i + 1}.txt`);
            fs.writeFileSync(filePath, Buffer.from(share).toString('hex'), 'utf8');
        });
        console.log(`Shares saved securely to ${outputDir}`);
    }

    /**
     * Unlocks the Cipher using provided shares and optional password.
     * @param providedShares Array of share strings (hex).
     * @param password Optional password.
     */
    async unlock(providedShares: string[], password?: string): Promise<void> {
        if (this.passwordHash && crypto.createHash('sha256').update(password ?? '').digest('hex') !== this.passwordHash) {
            throw new Error('Invalid password');
        }

        if (providedShares.length < this.threshold) {
            throw new Error(`Need at least ${this.threshold} shares to unlock`);
        }

        const sharesUint8 = providedShares.map(s => Uint8Array.from(Buffer.from(s, 'hex')));
        this.masterKey = Buffer.from(await Shamir.combine(sharesUint8));

        // If file exists, decrypt entire vault with integrity check
        if (this._encryptedVault) {
            const { iv, tag, ciphertext, hmac } = this._encryptedVault;
            const decryptedJson = Encryption.decrypt({ iv, tag, ciphertext }, this.masterKey);
            const computedHmac = crypto.createHmac('sha256', this.masterKey).update(decryptedJson).digest('hex');
            if (hmac !== computedHmac) throw new Error('Vault tampered!');
            this.secrets = JSON.parse(decryptedJson);
        }

        // Load SEK
        const encSek = this.secrets['ENCRYPTED_SEK'];
        if (!encSek) throw new Error('ENCRYPTED_SEK not found');
        const sekHex = Encryption.decrypt(encSek, this.masterKey);
        this.sek = Buffer.from(sekHex, 'hex');

        this.locked = false;
        console.log('Cipher unlocked. SEK loaded in memory.');
        this.logOperation('unlock', { timestamp: Date.now() });
    }

    /**
     * Locks the Cipher, clearing keys from memory.
     */
    lock(): void {
        this.masterKey = null;
        this.sek = null;
        this.locked = true;
        console.log('Cipher locked.');
        this.logOperation('lock', { timestamp: Date.now() });
    }

    /**
     * Rotates the master key and re-encrypts the vault.
     * @returns New shares as hex strings.
     */
    async rotateMasterKey(): Promise<string[]> {
        if (this.locked) throw new Error('Cipher is locked! Cannot rotate.');
        const oldMasterKey = this.masterKey!;
        this.masterKey = crypto.randomBytes(32);
        this.shares = await Shamir.split(this.masterKey, this.numShares, this.threshold);

        // Re-encrypt SEK and all secrets with new master key
        this.secrets['ENCRYPTED_SEK'] = Encryption.encrypt(this.sek!.toString('hex'), this.masterKey);
        // Note: Individual secrets are encrypted with SEK, so no need to re-encrypt them

        this.saveToFile();
        this.logOperation('rotateMasterKey', { timestamp: Date.now() });
        return this.shares.map(s => Buffer.from(s).toString('hex'));
    }

    /**
     * Writes a secret to the vault, optionally with a version.
     * @param key Key for the secret.
     * @param data Data to encrypt.
     * @param version Optional version string.
     */
    write(key: string, data: string, version: string | null = null): void {
        if (this.locked) throw new Error('Cipher is locked! Cannot write.');
        if (typeof key !== 'string' || key.length === 0) throw new Error('Key must be a non-empty string');
        if (typeof data !== 'string') throw new Error('Data must be a string');

        const enc = Encryption.encrypt(data, this.sek!);
        const versionKey = version ? `${key}:${version}` : `${key}:${Date.now()}`;
        this.secrets[versionKey] = enc;

        if (this.persistent) this._scheduleSave();
        console.log(`Secret written to path: ${versionKey}`);
        this.logOperation('write', { key: versionKey, timestamp: Date.now() });
    }

    /**
     * Reads a secret from the vault, optionally by version.
     * @param key Key for the secret.
     * @param version Optional version string; if null, reads latest.
     * @returns Decrypted data or null if not found.
     */
    read(key: string, version: string | null = null): string | null {
        if (this.locked) throw new Error('Cipher is locked! Cannot read.');

        let versionKey: string;
        if (version) {
            versionKey = `${key}:${version}`;
        } else {
            // Find latest version
            const matchingKeys = Object.keys(this.secrets).filter(k => k.startsWith(`${key}:`));
            if (matchingKeys.length === 0) return null;
            versionKey = matchingKeys.sort().pop()!;
        }

        const enc = this.secrets[versionKey];
        if (!enc) return null;

        const data = Encryption.decrypt(enc, this.sek!);
        this.logOperation('read', { key: versionKey, timestamp: Date.now() });
        return data;
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
        console.log('Secrets flushed to disk immediately.');
    }

    saveToFile(): void {
        if (!this.masterKey) throw new Error('Cannot save without master key');
        const vaultString = JSON.stringify(this.secrets, null, 2);
        const encryptedVault = Encryption.encrypt(vaultString, this.masterKey);
        const hmac = crypto.createHmac('sha256', this.masterKey).update(vaultString).digest('hex');
        const dataToSave = { ...encryptedVault, hmac };
        fs.writeFileSync(this.filePath, JSON.stringify(dataToSave), 'utf-8');
        if (process.platform !== 'win32') {
            fs.chmodSync(this.filePath, '600');
        }
    }

    /**
     * Logs an operation to the audit log.
     * @param operation Operation name.
     * @param details Details object.
     */
    logOperation(operation: string, details: Record<string, any>): void {
        if (!this.auditLogPath) return;
        const timestamp = new Date().toISOString();
        const logEntry = `${timestamp} - ${operation}: ${JSON.stringify(details)}\n`;
        fs.appendFileSync(this.auditLogPath, logEntry, 'utf8');
    }

    /**
     * Backs up the vault to a specified path.
     * @param backupPath Path to save backup.
     */
    backup(backupPath: string): void {
        if (!this.persistent || !fs.existsSync(this.filePath)) throw new Error('No vault to backup');
        fs.copyFileSync(this.filePath, backupPath);
        console.log(`Vault backed up to ${backupPath}`);
        this.logOperation('backup', { path: backupPath, timestamp: Date.now() });
    }

    /**
     * Restores the vault from a backup.
     * @param backupPath Path to backup file.
     */
    restore(backupPath: string): void {
        if (!fs.existsSync(backupPath)) throw new Error('Backup file does not exist');
        this._encryptedVault = JSON.parse(fs.readFileSync(backupPath, 'utf-8'));
        console.log(`Vault restored from ${backupPath}`);
        this.logOperation('restore', { path: backupPath, timestamp: Date.now() });
    }

    /**
     * Starts an HTTPS server for remote access (optional).
     * Requires tlsCertPath and tlsKeyPath in constructor.
     */
    startServer(): void {
        if (!this.tlsCert || !this.tlsKey) throw new Error('TLS cert and key required for server');
        const app = express();
        app.use(express.json());

        app.post('/unlock', async (req, res) => {
            try {
                await this.unlock(req.body.shares, req.body.password);
                res.status(200).send('Unlocked');
            } catch (e: any) {
                res.status(400).send(e.message);
            }
        });

        app.post('/lock', (req, res) => {
            this.lock();
            res.status(200).send('Locked');
        });

        app.post('/write', (req, res) => {
            try {
                this.write(req.body.key, req.body.data, req.body.version);
                res.status(200).send('Written');
            } catch (e: any) {
                res.status(400).send(e.message);
            }
        });

        app.get('/read', (req, res) => {
            try {
                const data = this.read(req.query.key as string, req.query.version as string);
                res.status(200).json({ data });
            } catch (e: any) {
                res.status(400).send(e.message);
            }
        });

        // Add more endpoints as needed

        this.server = https.createServer({ cert: this.tlsCert, key: this.tlsKey }, app).listen(this.port, () => {
            console.log(`Server running on https://localhost:${this.port}`);
        });
    }

    stopServer(): void {
        if (this.server) this.server.close();
    }
}

// ===== Demo =====
(async () => {
    const cipher = new Cipher({ persistent: true, autoSaveInterval: 5000 });
    if (!cipher['secrets']['ENCRYPTED_SEK']) await cipher.init();

    // Example: save shares
    // cipher.saveShares('./shares');

    await cipher.unlock([/* hex shares */]); // Provide hex shares

    cipher.write('secret/foo', 'secret data 1');
    cipher.write('secret/bar', 'secret data 2');

    console.log('Read secret foo:', cipher.read('secret/foo'));

    cipher.lock();
})();