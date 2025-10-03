import fs from 'fs';
import crypto from 'crypto';
//@ts-ignore
import Loki from 'lokijs';
import Ajv from 'ajv';
import path from "path";

// Custom type definitions for LokiJS 1.5.12
interface LokiCollection {
    name: string;
    insert(doc: any): any;
    find(query?: any): any[];
    findAndRemove(query?: any): void;
    get(id: number): any;
    chain(): { find(query?: any): { simplesort(prop: string, isDesc?: boolean): { data(): any[] } } };
}

interface Loki {
    getCollection(name: string): LokiCollection | null;
    addCollection(name: string, options?: any): LokiCollection;
    saveDatabase(callback: (err?: any) => void): void;
}


interface ICipher {
    readonly: boolean;
    locked: boolean;
    path: string;
    password: string;
    size: number;
}

interface ICollection {
    name: 'users';
    schema: any;
}

const algorithm = 'aes-256-gcm';
const keyLen = 32;
const ivLen = 12;
const saltLen = 16;
const tagLen = 16;

class EncryptedFsAdapter {
    private password: string;

    constructor(password: string) {
        this.password = password;
    }

    private deriveKey(salt: Buffer): Buffer {
        return crypto.pbkdf2Sync(this.password, salt, 100000, keyLen, 'sha256');
    }

    loadDatabase(dbname: string, callback: (err: any, data?: string) => void): void {
        fs.readFile(dbname, (err, data) => {
            if (err) {
                if (err.code === 'ENOENT') {
                    return callback(null, '{}');
                }
                return callback(err);
            }
            try {
                const salt = data.slice(0, saltLen);
                const iv = data.slice(saltLen, saltLen + ivLen);
                const tag = data.slice(saltLen + ivLen, saltLen + ivLen + tagLen);
                const encrypted = data.slice(saltLen + ivLen + tagLen);
                const key = this.deriveKey(salt);
                const decipher = crypto.createDecipheriv(algorithm, key, iv);
                decipher.setAuthTag(tag);
                let decrypted = decipher.update(encrypted, undefined, 'utf8');
                decrypted += decipher.final('utf8');
                callback(null, decrypted);
            } catch (e) {
                callback(e);
            }
        });
    }

    saveDatabase(dbname: string, dbstring: string, callback: (err?: any) => void): void {
        try {
            const salt = crypto.randomBytes(saltLen);
            const iv = crypto.randomBytes(ivLen);
            const key = this.deriveKey(salt);
            const cipher = crypto.createCipheriv(algorithm, key, iv);
            let encrypted = cipher.update(dbstring, 'utf8');
            encrypted = Buffer.concat([encrypted, cipher.final()]);
            const tag = cipher.getAuthTag();
            const data = Buffer.concat([salt, iv, tag, encrypted]);
            fs.writeFile(dbname, data, callback);
        } catch (e) {
            callback(e);
        }
    }
}

class CipherCollection {
    private cipher: Cipher;
    private collection: LokiCollection;
    private ajv: Ajv;
    private schema: any;

    constructor(cipher: Cipher, collection: LokiCollection, schema: any) {
        this.cipher = cipher;
        this.collection = collection;
        this.ajv = new Ajv({ allErrors: true });
        this.schema = schema;
    }

    private validateSchema(data: any): void {
        if (this.schema && Object.keys(this.schema).length > 0) {
            const validate = this.ajv.compile(this.schema);
            if (!validate(data)) {
                throw new Error(`Schema validation failed: ${JSON.stringify(validate.errors)}`);
            }
        }
    }

    async insert(key: { name: string }, secret: any, meta: { readonly?: boolean; version?: number } = {}): Promise<number> {
        if (!this.cipher.canWrite(meta)) {
            throw new Error('Cannot insert: readonly mode');
        }
        const name = key.name;
        const existing = this.collection.find({ name });
        if (existing.length > 0) {
            throw new Error('Key already exists; use update instead');
        }
        const version = meta.version || 1;
        if (version < 1) {
            throw new Error('Version must be at least 1');
        }
        const doc = { name, secret, version };
        this.validateSchema(doc);
        const inserted = this.collection.insert(doc);
        await this.cipher.save();
        return inserted.$loki;
    }

    async update(key: { name: string }, secret: any, meta: { readonly?: boolean; version?: number } = {}): Promise<number> {
        if (!this.cipher.canWrite(meta)) {
            throw new Error('Cannot update: readonly mode');
        }
        const name = key.name;
        const existing = this.collection.chain().find({ name }).simplesort('version', true).data();
        if (existing.length === 0) {
            throw new Error('Key does not exist; use insert instead');
        }
        const maxVersion = existing[existing.length - 1].version;
        const version = meta.version || maxVersion + 1;
        if (version <= maxVersion) {
            throw new Error('Version must be higher than previous');
        }
        const doc = { name, secret, version };
        this.validateSchema(doc);
        const inserted = this.collection.insert(doc);
        await this.cipher.save();
        return inserted.$loki;
    }

    async delete(key: { name: string }, meta: { readonly?: boolean; version?: number } = {}): Promise<void> {
        if (!this.cipher.canWrite(meta)) {
            throw new Error('Cannot delete: readonly mode');
        }
        const name = key.name;
        const query: any = { name };
        if (meta.hasOwnProperty('version')) {
            query.version = meta.version;
        }
        this.collection.findAndRemove(query);
        await this.cipher.save();
    }

    find(key: { name: string }): { _id: number; name: string } | null {
        const name = key.name;
        const existing = this.collection.chain().find({ name }).simplesort('version', true).data();
        if (existing.length === 0) {
            return null;
        }
        const latest = existing[existing.length - 1];
        return { _id: latest.$loki, name: latest.name };
    }

    unseal(_id: number): any {
        const doc = this.collection.get(_id);
        if (!doc) {
            throw new Error('Document not found');
        }
        return doc.secret;
    }
}

class Cipher implements Loki {
    private settings: ICipher;
    private collections: Map<string, { collection: LokiCollection; schema: any }>;
    private readyPromise: Promise<void>;
    getCollection: (name: string) => LokiCollection | null;
    addCollection: (name: string, options?: any) => LokiCollection;
    saveDatabase: (callback: (err?: any) => void) => void;

    constructor(settings: ICipher, collections: ICollection[] = [{ name: 'users', schema: {} }]) {
        const adapter = new EncryptedFsAdapter(settings.password);
        this.collections = new Map();
        this.settings = settings;
        if(!fs.existsSync(settings.path))
            fs.mkdirSync(settings.path);

        const lokiInstance = new Loki(`${settings.path}/database.db`, {
            adapter,
            autoload: true,
            autosave: false,
            autoloadCallback: (err?: any) => {
                if (err) {
                    console.error('Autoload error:', err);
                    throw err;
                }
                this.databaseInitialize(collections);
                console.log('Collections initialized:', Array.from(this.collections.keys()));
            }
        });
        this.getCollection = lokiInstance.getCollection.bind(lokiInstance);
        this.addCollection = lokiInstance.addCollection.bind(lokiInstance);
        this.saveDatabase  = lokiInstance.saveDatabase.bind(lokiInstance);
        // Create a promise that resolves when initialization is complete
        this.readyPromise = new Promise((resolve, reject) => {
            lokiInstance.on('loaded', () => resolve());
            lokiInstance.on('error', (err:any) => reject(err));
        });
    }

    private databaseInitialize(collections: ICollection[]): void {
        for (const col of collections) {
            let collection = this.getCollection(col.name);
            if (collection === null) {
                console.log(`Creating collection: ${col.name}`);
                collection = this.addCollection(col.name, {
                    indices: ['name', 'version'],
                });
            } else {
                console.log(`Found existing collection: ${col.name}`);
            }
            this.collections.set(col.name, { collection, schema: col.schema });
        }
    }

    canWrite(meta: any): boolean {
        const readonlyOverride = meta.hasOwnProperty('readonly') ? meta.readonly : this.settings.readonly;
        return !readonlyOverride;
    }

    async save(): Promise<void> {
        return new Promise((resolve, reject) => {
            this.saveDatabase((err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    collection(name: string): CipherCollection {
        const col = this.collections.get(name);
        if (!col) {
            throw new Error(`Collection ${name} not found`);
        }
        return new CipherCollection(this, col.collection, col.schema);
    }

    // Wait for database initialization
    async ready(): Promise<void> {
        return this.readyPromise;
    }
}
const cipher = new Cipher({
    size     : 100,
    password : 'b1mujx22',
    path     : path.resolve(__dirname,'./vault/secrets'),
    locked   : true,
    readonly : true
}, [{
        name: 'users',
        schema: {
            type: 'object',
            properties: {
                name: { type: 'string' },
                secret: { type: 'object', properties: { password: { type: 'string' } }, required: ['password'] },
                version: { type: 'number', minimum: 1 }
            },
            required: ['name', 'secret', 'version']
        }
    }
]);

async function run() {
    try {
        // Wait for the Cipher instance to be fully initialized
        await cipher.ready();
        const users = cipher.collection('users');
        const id = await users.insert(
            { name: 'vadim' },
            { password: '12345' },
            { readonly: false, version: 1 }
        );
        console.log(`Inserted vadim, id: ${id}`);

        const found = users.find({ name: 'vadim' });
        if (found) {
            const secret = users.unseal(found._id);
            console.log(`Unsealed: ${JSON.stringify(secret)}`);
        }
    } catch (e:any) {
        console.error(`Error: ${e.message}`);
    }
}

run();