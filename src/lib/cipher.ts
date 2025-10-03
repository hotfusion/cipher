import * as fs from 'fs';
import * as crypto from 'crypto';
//@ts-ignore
import * as Loki from 'lokijs';
import * as Ajv from 'ajv';
import * as path from "path"
// Custom type definitions for LokiJS 1.5.12
interface LokiCollection {
    name: string;
    insert(doc: any): any;
    find(query?: any): any[];
    findAndRemove(query?: any): void;
    get(id: number): any;
    chain(): { find(query?: any): { simplesort(prop: string, isDesc?: boolean): { data(): any[] } } };

    find(query?: any): any[];
    insert(doc: any): any;
    // Add missing methods
    findOne(query: any): any | null;
    update(doc: any): void;
    // Include other existing properties/methods as needed
    data: any[];
    idIndex: number[] | null;
    binaryIndices: { [key: string]: { name: string; dirty: boolean; values: number[] } };
    uniqueNames: string[];
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
    name: string;
    schema: any;
}

const algorithm = 'aes-256-gcm';
const keyLen = 32;
const ivLen = 12;
const saltLen = 16;
const tagLen = 16;

class EncryptedFsAdapter {
    private password: string;
    private lastDecryptedContent: string | null = null; // Store decrypted content

    constructor(password: string) {
        this.password = password;
    }

    private deriveKey(salt: Buffer): Buffer {
        return crypto.pbkdf2Sync(this.password, salt, 100000, keyLen, 'sha256');
    }

    loadDatabase(dbname: string, callback: (err: any, data?: string) => void): void {
        console.log(`Attempting to load database from: ${dbname}`);
        if (!fs.existsSync(dbname)) {
            console.log(`Database file ${dbname} does not exist, returning empty DB`);
            this.lastDecryptedContent = '{}';
            return callback(null, '{}');
        }
        fs.readFile(dbname, (err, data) => {
            if (err) {
                console.error(`Error reading database file ${dbname}:`, err);
                return callback(err);
            }
            try {
                console.log(`Reading ${data.length} bytes from ${dbname}`);
                const salt = data.slice(0, saltLen);
                const iv = data.slice(saltLen, saltLen + ivLen);
                const tag = data.slice(saltLen + ivLen, saltLen + ivLen + tagLen);
                const encrypted = data.slice(saltLen + ivLen + tagLen);
                const key = this.deriveKey(salt);
                const decipher = crypto.createDecipheriv(algorithm, key, iv);
                decipher.setAuthTag(tag);
                let decrypted = decipher.update(encrypted, undefined, 'utf8');
                decrypted += decipher.final('utf8');
                console.log(`Decrypted database content: ${decrypted}`);
                this.lastDecryptedContent = decrypted; // Store decrypted content
                callback(null, decrypted);
            } catch (e) {
                console.error(`Error decrypting database ${dbname}:`, e);
                callback(e);
            }
        });
    }

    saveDatabase(dbname: string, dbstring: string, callback: (err?: any) => void): void {
        console.log(`Attempting to save database to: ${dbname}`);
        console.log(`Database content to save: ${dbstring}`);
        try {
            const salt = crypto.randomBytes(saltLen);
            const iv = crypto.randomBytes(ivLen);
            const key = this.deriveKey(salt);
            const cipher = crypto.createCipheriv(algorithm, key, iv);
            let encrypted = cipher.update(dbstring, 'utf8');
            encrypted = Buffer.concat([encrypted, cipher.final()]);
            const tag = cipher.getAuthTag();
            const data = Buffer.concat([salt, iv, tag, encrypted]);
            fs.writeFile(dbname, data, (err) => {
                if (err) {
                    console.error(`Error writing database to ${dbname}:`, err);
                    return callback(err);
                }
                console.log(`Successfully saved database to ${dbname} (${data.length} bytes)`);
                if (fs.existsSync(dbname)) {
                    console.log(`Confirmed database file exists at ${dbname}`);
                } else {
                    console.error(`Database file ${dbname} was not created`);
                }
                callback(null);
            });
        } catch (e) {
            console.error(`Error encrypting database for ${dbname}:`, e);
            callback(e);
        }
    }

    getLastDecryptedContent(): string | null {
        return this.lastDecryptedContent;
    }
}

class CipherCollection {
    private cipher: Cipher;
    private collection: LokiCollection;
    private ajv: Ajv.default;
    private schema: { keySchema?: any };

    constructor(cipher: Cipher, collection: LokiCollection, schema: { keySchema?: any }) {
        this.cipher = cipher;
        this.collection = collection;
        this.ajv = new Ajv.default({ allErrors: true });
        this.schema = schema;
    }

    private validateKey(key: any): void {
        if (this.schema?.keySchema) {
            const validate = this.ajv.compile(this.schema.keySchema);
            if (!validate(key)) {
                throw new Error('Key validation failed: ' + JSON.stringify(validate.errors, null, 2));
            }
        }
    }

    async insert(key: any, secret: any, meta: { readonly?: boolean; version?: number, __created?: number, __updated?: number } = {}): Promise<number> {
        meta.__created = Date.now();
        meta.__updated = Date.now();
        if (!this.cipher.canWrite(meta)) {
            throw new Error('Cannot insert: readonly mode');
        }
        this.validateKey(key);
        const id = key.id; // Use key.id as the document's id
        const keyName = key.keyName || 'id'; // Default to 'id' if keyName not provided
        const existing = this.collection.find({ id });
        if (existing.length > 0) {
            throw new Error('Key already exists; use update instead');
        }
        const version = meta.version || 1;
        if (version < 1) {
            throw new Error('Version must be at least 1');
        }
        meta.version = version; // Set meta.version to match document version
        const doc = { id, secret, version, meta, keyName }; // Store keyName in document
        console.log('Inserting document:', JSON.stringify({ id, version, meta, keyName }, null, 2)); // Debug log (exclude secret)
        const inserted = this.collection.insert(doc);
        await this.cipher.save();
        return inserted.$loki;
    }

    async update(key: any, secret: any, meta: { readonly?: boolean; version?: number, __created?: number, __updated?: number } = {}): Promise<number> {
        meta.__updated = Date.now();
        if (!this.cipher.canWrite(meta)) {
            throw new Error('Cannot update: readonly mode');
        }
        this.validateKey(key);
        const id = key.id;
        const keyName = key.keyName || 'id';
        const existing = this.collection.chain().find({ id }).simplesort('version', true).data();
        if (existing.length === 0) {
            throw new Error('Key does not exist; use insert instead');
        }
        const maxVersion = existing[existing.length - 1].version;
        const version = meta.version || maxVersion + 1;
        if (version <= maxVersion) {
            throw new Error('Version must be higher than previous');
        }
        meta.version = version; // Set meta.version to match document version
        const doc = { id, secret, version, meta, keyName };
        console.log('Updating document:', JSON.stringify({ id, version, meta, keyName }, null, 2)); // Debug log (exclude secret)
        const inserted = this.collection.insert(doc);
        await this.cipher.save();
        return inserted.$loki;
    }

    async delete(key: any, meta: { readonly?: boolean; version?: number } = {}): Promise<void> {
        if (!this.cipher.canWrite(meta)) {
            throw new Error('Cannot delete: readonly mode');
        }
        this.validateKey(key);
        const id = key.id;
        const query: any = { id };
        if (meta.hasOwnProperty('version')) {
            query.version = meta.version;
        }
        this.collection.findAndRemove(query);
        await this.cipher.save();
    }

    find(key: any): { key: { [key: string]: string }, meta: { version: number, readonly?: boolean }, _id: number } | null {
        this.validateKey(key);
        const id = key.id; // Use key.id to locate the document
        const existing = this.collection.chain().find({ id }).simplesort('version', true).data();
        if (existing.length === 0) {
            return null;
        }
        const latest = existing[existing.length - 1];
        const keyName = latest.keyName || 'id'; // Use stored keyName or default to 'id'
        return {
            key: { [keyName]: latest.id },
            meta: {
                version: latest.version,
                readonly: latest.meta.readonly
            },
            _id: latest.$loki // Include _id for unseal
        };
    }

    unseal(_id: number): any {
        const doc = this.collection.get(_id);
        if (!doc) {
            throw new Error('Document not found');
        }
        return doc.secret;
    }

    list(): Array<{ key: { [key: string]: string }, meta: { version: number, readonly?: boolean } }> {
        return this.collection.find().map(doc => ({
            key: { [doc.keyName || 'id']: doc.id }, // Use stored keyName or default to 'id'
            meta: {
                version: doc.version,
                readonly: doc.meta.readonly
            }
        }));
    }
}

export class Cipher implements Loki {
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
        console.log(`Ensuring directory exists: ${settings.path}`);
        if (!fs.existsSync(settings.path)) {
            fs.mkdirSync(settings.path, { recursive: true });
            console.log(`Created directory: ${settings.path}`);
        } else {
            console.log(`Directory already exists: ${settings.path}`);
        }

        const lokiInstance = new (Loki.default || Loki)(`${settings.path}/database.db`, {
            adapter,
            autoload: true,
            autosave: false, // Rely on explicit saves
            autoloadCallback: (err?: any) => {
                if (err) {
                    console.error('Autoload error:', err);
                    throw err;
                }
                // Debug: Log raw database collections
                const rawCollections = (this as any).lokiInstance.collections
                    ? (this as any).lokiInstance.collections.map((c: any) => c.name)
                    : [];
                console.log('Raw database collections:', rawCollections);
                // Get decrypted content from adapter
                const decryptedContent = (adapter as EncryptedFsAdapter).getLastDecryptedContent();
                let dbContent: any = {};
                if (decryptedContent) {
                    try {
                        dbContent = JSON.parse(decryptedContent);
                        console.log('Parsed decrypted database content:', JSON.stringify(dbContent.collections?.map((c: any) => c.name) || [], null, 2));
                    } catch (e) {
                        console.error('Error parsing decrypted content:', e);
                        throw e;
                    }
                }
                // Process all collections dynamically
                if (dbContent.collections) {
                    for (const col of dbContent.collections) {
                        // Check if the collection exists in the provided collections array
                        const collectionConfig = collections.find(c => c.name === col.name);
                        if (collectionConfig && !this.getCollection(col.name)) {
                            console.log(`Manually registering collection: ${col.name}`);
                            const collection = this.addCollection(col.name, {
                                indices: ['id', 'version'],
                                unique: ['id'],
                            });
                            // Populate collection with deserialized data
                            if (col.data && Array.isArray(col.data)) {
                                col.data.forEach((doc: any) => {
                                    try {
                                        // Remove $loki to avoid ID conflicts
                                        const newDoc = { ...doc };
                                        delete newDoc.$loki;
                                        // Check if document exists by id
                                        const existingDoc = collection.findOne({ id: doc.id });
                                        if (existingDoc) {
                                            console.log(`Document with id ${doc.id} already exists, updating`);
                                            Object.assign(existingDoc, newDoc);
                                            collection.update(existingDoc);
                                        } else if (doc.id && doc.secret && doc.meta) {
                                            console.log(`Inserting document with id ${doc.id}`);
                                            collection.insert(newDoc);
                                        } else {
                                            console.log(`Skipping invalid document: ${JSON.stringify(doc)}`);
                                        }
                                    } catch (e) {
                                        console.error(`Error processing document with id ${doc.id || 'unknown'}:`, e);
                                    }
                                });
                                console.log(`Processed ${col.data.length} documents for collection ${col.name}`);
                            }
                        }
                    }
                }
                this.databaseInitialize(collections);
                console.log('Collections initialized:', Array.from(this.collections.keys()));
            }
        });
        this.getCollection = lokiInstance.getCollection.bind(lokiInstance);
        this.addCollection = lokiInstance.addCollection.bind(lokiInstance);
        this.saveDatabase = lokiInstance.saveDatabase.bind(lokiInstance);
        (this as any).lokiInstance = lokiInstance; // Store for debugging
        this.readyPromise = new Promise((resolve, reject) => {
            lokiInstance.on('loaded', () => {
                console.log('Database loaded successfully');
                const allCollections = lokiInstance.listCollections().map((col: any) => col.name);
                console.log('Collections in database:', allCollections);
                resolve();
            });
            lokiInstance.on('error', (err: any) => {
                console.error('Database error:', err);
                reject(err);
            });
        });
    }

    private databaseInitialize(collections: ICollection[]): void {
        for (const col of collections) {
            let collection = this.getCollection(col.name);
            if (collection === null) {
                console.log(`Creating collection: ${col.name}`);
                collection = this.addCollection(col.name, {
                    indices: ['id', 'version'],
                    unique: ['id'],
                });
            } else {
                console.log(`Found existing collection: ${col.name}`);
                console.log(`Documents in ${col.name}:`, collection.find().length);
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
                if (err) {
                    console.error('Save error:', err);
                    reject(err);
                } else {
                    console.log('Database save completed');
                    resolve();
                }
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

    async ready(): Promise<void> {
        return this.readyPromise;
    }
}






/*const cipher = new Cipher({
    size     : 100,
    password : 'b1mujx22',
    path     : path.resolve(__dirname,'./vault/secrets'),
    locked   : true,
    readonly : true
}, [{
        name: 'users',
        schema: {
            name: 'object',
            properties: {
                id: { type: 'string' }
            },
            required: ['name', 'secret', 'version']
        }
    }
]);*/

/*async function run() {
    try {
        // Wait for the Cipher instance to be fully initialized
        await cipher.ready();
        const users = cipher.collection('users');
        /!*const id = await users.insert(
            { id: 'vadime', name : 'a' },
            { password: '12345' },
            { readonly: false, version: 1 }
        );
        console.log(`Inserted vadim, id: ${id}`);*!/

        const found = users.find({ id: 'vadime' });
        console.log(found)
        if (found) {
            const secret = users.unseal(found._id);
            console.log(`Unsealed: ${JSON.stringify(secret)}`);
        }
    } catch (e:any) {
        console.error(e);
    }
}

run();*/

