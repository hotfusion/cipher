/*
import { EncryptedFolder } from './luks';
import pkcs11 from 'pkcs11js';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import winston from 'winston';
//@ts-ignore
import * as Loki from 'lokijs'
interface DBRecord {
    key: Record<string, any>;
    _encrypted: Record<string, Buffer>;
    _timestamp: number;
}

interface IHSM {
    containerPath: string;
    mountPath: string;
    password: string;
    pin: string;
    hsmSlot?: number;
    maxMemoryMB?: number;
    logLevel?: string;
}

export class HSM {
    private readonly encryptedFolder: EncryptedFolder;
    private readonly session: Buffer;
    private readonly keyHandle: Buffer;
    private readonly dbPath: string;
    private readonly snapshotPath: string;
    private readonly maxMemoryBytes: number;
    private pkcs11Lib: pkcs11.PKCS11;
    private store: Map<string, DBRecord> = new Map();
    private logger: winston.Logger;

    constructor(options: IHSM) {
        if (!options.pin) {
            throw new Error('HSM PIN is required. You must provide hsmPin in options.');
        }

        if(!fs.existsSync(options.containerPath))
            fs.mkdirSync(path.dirname(options.containerPath),{recursive:true});

        // Initialize logger
        this.logger = winston.createLogger({
            level: options.logLevel || 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.printf(({ timestamp, level, message }) => {
                    return `${timestamp} [${level.toUpperCase()}]: ${message}`;
                })
            ),
            transports: [new winston.transports.Console()]
        });

        // Setup encrypted folder
        this.encryptedFolder = new EncryptedFolder({
            containerPath: options.containerPath,
            mountPath: options.mountPath,
            password: options.password,
            logLevel: options.logLevel
        });

        this.dbPath = path.join(options.mountPath, 'memdb');
        this.snapshotPath = path.join(this.dbPath, 'snapshot.json');
        this.maxMemoryBytes = (options.maxMemoryMB || 2048) * 1024 * 1024;

        this.ensureSoftHSM2Config();
        this.ensureSoftHSM2Installed();

        // Initialize token if it doesn't exist, using the PIN provided
        this.ensureTokenInitialized(options.pin, options.hsmSlot || 0);

        // Load SoftHSM2 library
        this.pkcs11Lib = new pkcs11.PKCS11();
        try {
            this.pkcs11Lib.load('/usr/lib/softhsm/libsofthsm2.so');
            this.logger.info('SoftHSM2 library loaded');
        } catch (error) {
            this.logger.error('Failed to load SoftHSM2 library');
            throw error;
        }

        this.pkcs11Lib.C_Initialize();

        // Get slot and open session
        const slots = this.pkcs11Lib.C_GetSlotList(true);
        if (!slots.length) throw new Error('No slots with tokens found');

        const slotHandle = slots[options.hsmSlot || 0];
        if (!slotHandle) throw new Error(`Slot index ${options.hsmSlot} invalid`);

        this.session = this.pkcs11Lib.C_OpenSession(
            slotHandle,
            pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION
        );

        try {
            this.pkcs11Lib.C_Login(this.session, pkcs11.CKU_USER, options.pin);
        } catch {
            throw new Error('HSM login failed. Check your hsmPin.');
        }

        this.logger.info('Logged into SoftHSM2');
        this.keyHandle = this.findOrCreateKey();
    }
    /!**
     * Ensure SoftHSM2 configuration exists, create if missing
     *!/
    private ensureSoftHSM2Config(): void {
        const { execSync } = require('child_process');
        const os = require('os');
        const fs = require('fs');
        const path = require('path');

        const homeDir = os.homedir();
        const configDir = path.join(homeDir, '.softhsm');
        const configPath = path.join(configDir, 'softhsm2.conf');
        const tokenDir = path.join(configDir, 'tokens');

        // Create config directory if missing
        if (!fs.existsSync(configDir)) {
            fs.mkdirSync(configDir, { recursive: true });
            this.logger.info(`Created SoftHSM2 config directory: ${configDir}`);
        }

        // Create token directory if missing
        if (!fs.existsSync(tokenDir)) {
            fs.mkdirSync(tokenDir, { recursive: true });
            this.logger.info(`Created SoftHSM2 token directory: ${tokenDir}`);
        }

        // Create config file if missing
        if (!fs.existsSync(configPath)) {
            const configContent = [
                `directories.tokendir = ${tokenDir}`,
                `objectstore.backend = file`,
                `log.level = INFO`
            ].join('\n');
            fs.writeFileSync(configPath, configContent);
            this.logger.info(`Created SoftHSM2 config file: ${configPath}`);
        }

        // Set environment variable so SoftHSM2 finds it
        process.env.SOFTHSM2_CONF = configPath;
        this.logger.debug(`SOFTHSM2_CONF set to ${configPath}`);
    }
    /!**
     * Check if SoftHSM2 is installed, install if not
     *!/
    private ensureSoftHSM2Installed(): void {
        const { execSync } = require('child_process');

        try {
            // Check if softhsm2 is installed
            execSync('which softhsm2-util', { stdio: 'ignore' });
            this.logger.debug('SoftHSM2 already installed');
        } catch {
            this.logger.warn('SoftHSM2 not found. Installing...');
            try {
                execSync('sudo apt-get update && sudo apt-get install -y softhsm2', {
                    stdio: 'inherit'
                });
                this.logger.info('SoftHSM2 installed successfully');
            } catch (error) {
                this.logger.error('Failed to install SoftHSM2', { error });
                throw new Error('SoftHSM2 installation failed. Please install manually: sudo apt-get install softhsm2');
            }
        }
    }

    /!**
     * Check if token is initialized, initialize if not
     *!/
    private ensureTokenInitialized(pin: string,slot:number): void {
        const { execSync } = require('child_process');
        const crypto = require('crypto');

        try {
            // List all slots
            const output = execSync('softhsm2-util --show-slots', { encoding: 'utf8' });
            const lines: any[] = output.split('\n');

            // Check if any token already exists
            const tokenLine: any = lines.find((line: any) => line.includes('Token Label'));
            if (tokenLine) {
                const match = tokenLine.match(/Slot (\d+)/);
                const slot = match ? parseInt(match[1], 10) : null;
                if (slot !== null) {
                    this.logger.debug(`Token already initialized in slot ${slot}`);
                    return; // Token exists, done
                }
            }

            // No token yet: initialize in first free slot
            const soPin = crypto.randomBytes(16).toString('hex');
            execSync(
                `softhsm2-util --init-token --free --label "MemDB-Token" --pin ${pin} --so-pin ${soPin}`,
                { stdio: 'inherit' }
            );

            this.logger.info(`Token initialized successfully (slot chosen automatically)`);
        } catch (err: any) {
            this.logger.error('Failed to initialize token', { error: err });
            throw new Error('Token initialization failed');
        }
    }


    /!**
     * Find existing key or create new one in HSM
     *!/
    private findOrCreateKey(): Buffer {
        // Try to find existing key
        const template = [
            { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
            { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_AES },
            { type: pkcs11.CKA_LABEL, value: 'memdb-key' }
        ];

        this.pkcs11Lib.C_FindObjectsInit(this.session, template);
        const handles = this.pkcs11Lib.C_FindObjects(this.session, 1);
        this.pkcs11Lib.C_FindObjectsFinal(this.session);

        if (handles.length > 0) {
            this.logger.info('Found existing HSM key');
            return handles[0];
        }

        // Create new key
        this.logger.info('Creating new HSM key');
        const keyTemplate = [
            { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_SECRET_KEY },
            { type: pkcs11.CKA_KEY_TYPE, value: pkcs11.CKK_AES },
            { type: pkcs11.CKA_LABEL, value: 'memdb-key' },
            { type: pkcs11.CKA_VALUE_LEN, value: 32 }, // 256-bit key
            { type: pkcs11.CKA_TOKEN, value: true },
            { type: pkcs11.CKA_ENCRYPT, value: true },
            { type: pkcs11.CKA_DECRYPT, value: true },
            { type: pkcs11.CKA_PRIVATE, value: true },
            { type: pkcs11.CKA_SENSITIVE, value: true },
            { type: pkcs11.CKA_EXTRACTABLE, value: false } // Key cannot be extracted
        ];

        return this.pkcs11Lib.C_GenerateKey(
            this.session,
            { mechanism: pkcs11.CKM_AES_KEY_GEN },
            keyTemplate
        );
    }

    /!**
     * Initialize database
     *!/
    async initialize(containerSizeMB: number = 512): Promise<void> {
        this.logger.info('Initializing database...');

        try {
            // Create container if doesn't exist
            if (!fs.existsSync(this.encryptedFolder['containerPath'])) {
                this.logger.info('Creating new encrypted container...');
                this.encryptedFolder.createContainer(containerSizeMB);

                if (!fs.existsSync(this.dbPath)) {
                    fs.mkdirSync(this.dbPath, { recursive: true });
                }

                this.encryptedFolder.close();
            }

            this.logger.info(`Database loaded: ${this.store.size} records in memory`);
        } catch (error) {
            this.logger.error('Initialization failed', { error });
            throw error;
        }
    }

    /!**
     * Encrypt data using SoftHSM2
     *!/
    private encrypt(plaintext: string): Buffer {
        const plaintextBuffer = Buffer.from(plaintext, 'utf8');

        // Generate random IV
        const iv = crypto.randomBytes(16);

        // Initialize encryption
        this.pkcs11Lib.C_EncryptInit(
            this.session,
            { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter: iv },
            this.keyHandle
        );

        // Encrypt data
        const encrypted = this.pkcs11Lib.C_Encrypt(
            this.session,
            plaintextBuffer,
            Buffer.alloc(plaintextBuffer.length + 32) // Extra space for padding
        );

        // Combine IV + encrypted data
        return Buffer.concat([iv, encrypted]);
    }

    /!**
     * Decrypt data using SoftHSM2
     *!/
    private decrypt(ciphertext: Buffer): string {
        // Extract IV and encrypted data
        const iv = ciphertext.subarray(0, 16);
        const encrypted = ciphertext.subarray(16);

        // Initialize decryption
        this.pkcs11Lib.C_DecryptInit(
            this.session,
            { mechanism: pkcs11.CKM_AES_CBC_PAD, parameter: iv },
            this.keyHandle
        );

        // Decrypt data
        const decrypted = this.pkcs11Lib.C_Decrypt(
            this.session,
            encrypted,
            Buffer.alloc(encrypted.length + 32)
        );

        return decrypted.toString('utf8');
    }

    /!**
     * Hash key object
     *!/
    private hashKey(key: Record<string, any>): string {
        const keyString = JSON.stringify(key, Object.keys(key).sort());
        return crypto.createHash('sha256').update(keyString).digest('hex');
    }

    /!**
     * Get stats
     *!/
    getStats(): {
        recordCount: number;
        estimatedMemoryMB: number;
        maxMemoryMB: number;
    } {
        const estimatedBytes = JSON.stringify(Array.from(this.store.values())).length;

        return {
            recordCount: this.store.size,
            estimatedMemoryMB: Math.round(estimatedBytes / (1024 * 1024) * 100) / 100,
            maxMemoryMB: this.maxMemoryBytes / (1024 * 1024)
        };
    }

    private checkMemoryUsage(): void {
        const stats = this.getStats();
        const usagePercent = (stats.estimatedMemoryMB / stats.maxMemoryMB) * 100;

        if (usagePercent > 90) {
            this.logger.warn(`Memory usage high: ${usagePercent.toFixed(1)}%`);
        }
    }

    /!**
     * Shutdown
     *!/
    async shutdown(): Promise<void> {
        this.logger.info('Shutting down database...');
        // Logout and close HSM session
        this.pkcs11Lib.C_Logout(this.session);
        this.pkcs11Lib.C_CloseSession(this.session);
        this.pkcs11Lib.C_Finalize();
        this.logger.info('Database shutdown complete');
    }
}

import {execSync} from "child_process";

(async () => {
    const hsm = new HSM({
        containerPath : path.resolve(__dirname,'./_.store/cipher.img'),
        mountPath     : path.resolve(__dirname,'./secret-folder'),
        password      : 'disk-password12',
        pin           : '1234',
        hsmSlot       : 0,
        maxMemoryMB   : 2048,
        logLevel      : 'debug'
    });

    // Initialize
    await hsm.initialize(512);


    const check = execSync(`mount | grep ${path.resolve(__dirname,'./secret-folder/database.db')} || true`).toString();
    if (!check.includes(path.resolve(__dirname,'./secret-folder/database.db'))) {
        throw new Error('Encrypted folder is NOT mounted — Loki will leak secrets!');
    }

// create database instance (in-memory, but can be saved later)
    const db = new Loki.default(path.resolve(__dirname,'./secret-folder/database.db'), {
        autoload: true,               // load if exists
        autoloadCallback: databaseInitialize,
        autosave: true,               // auto save
        autosaveInterval: 4000        // every 4s
    });

    function databaseInitialize() {
        let users = db.getCollection('users');

        if (users === null) {
            users = db.addCollection('users'); // create if not exists
        }

        // Insert some data
        users.insert({ name: 'Alice', age: 30 });
        users.insert({ name: 'Bob', age: 25 });
        users.insert({ name: 'Charlie', age: 35 });

        // Query data
        const result = users.find({ age: { '$gt': 26 } });
        console.log('Users over 26:', result);

        // Save database explicitly (optional if autosave is on)
        //db.saveDatabase();
    }

    // Save and shutdown
    //await db.saveToDisk();
    //await db.shutdown();
})()

*/
