import { execSync, spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import winston from 'winston';

interface EncryptedFolderOptions {
    containerPath: string;
    mountPath: string;
    password?: string;
    existingKey?: string;
    logLevel?: string;
}

interface KeyMetadata {
    salt: string;
    iterations: number;
    algorithm: string;
}

export class EncryptedFolder {
    private containerPath: string;
    private mountPath: string;
    private key: string;
    private mapperName: string;
    private isUnlocked: boolean = false;
    private logger: winston.Logger;
    private metadataPath: string;

    constructor(options: EncryptedFolderOptions) {
        this.containerPath = path.resolve(options.containerPath);
        this.mountPath = path.resolve(options.mountPath);
        this.mapperName = `encrypted_${crypto.randomBytes(8).toString('hex')}`;
        this.metadataPath = `${this.containerPath}.meta`;

        // Initialize Winston logger
        this.logger = winston.createLogger({
            level: options.logLevel || 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.printf(({ timestamp, level, message, stack }) => {
                    return `${timestamp} [${level.toUpperCase()}]: ${message}${stack ? '\n' + stack : ''}`;
                })
            ),
            transports: [
                new winston.transports.Console({
                    format: winston.format.combine(
                        winston.format.colorize(),
                        winston.format.printf(({ timestamp, level, message }) => {
                            return `${timestamp} ${level}: ${message}`;
                        })
                    )
                }),
                new winston.transports.File({
                    filename: 'encrypted-folder.log',
                    format: winston.format.json()
                })
            ]
        });

        if (!fs.existsSync(this.mountPath)) {
            fs.mkdirSync(this.mountPath, { recursive: true });
            this.logger.debug(`Created mount path: ${this.mountPath}`);
        }

        this.ensureCryptSetup();

        if (options.password) {
            // ✅ Try to load metadata if it exists
            const metadata = this.loadMetadata();
            if (metadata) {
                this.key = this.deriveKeyFromPassword(options.password, metadata);
                this.logger.info('Using password-derived key (metadata loaded).');
            } else {
                this.key = this.deriveKeyFromPassword(options.password);
                this.logger.info('Using password-derived key (new metadata saved).');
            }
        } else if (options.existingKey) {
            this.key = options.existingKey;
            this.logger.info('Using provided key.');
        } else {
            // ⚠️ Random key will not survive restart unless you save/export it
            this.key = crypto.randomBytes(32).toString('hex');
            this.logger.warn(
                'Generated new random key. ⚠️ This container cannot be reopened unless you save/export this key!'
            );
        }
    }

    private ensureCryptSetup(): void {
        try {
            execSync('which cryptsetup', { stdio: 'ignore' });
            this.logger.debug('cryptsetup found.');
        } catch {
            this.logger.warn('cryptsetup not found. Attempting to install...');
            try {
                execSync('sudo apt update && sudo apt install -y cryptsetup-bin', { stdio: 'inherit' });
                this.logger.info('cryptsetup installed successfully.');
            } catch (error) {
                this.logger.error('Failed to install cryptsetup', { error });
                throw new Error('cryptsetup installation failed. Please install manually.');
            }
        }
    }

    private deriveKeyFromPassword(password: string, metadata?: KeyMetadata): string {
        const salt = metadata?.salt || crypto.randomBytes(32).toString('hex');
        const iterations = metadata?.iterations || 100000;
        const algorithm = metadata?.algorithm || 'sha512';

        this.logger.debug('Deriving key from password', { iterations, algorithm });

        const derivedKey = crypto.pbkdf2Sync(
            password,
            Buffer.from(salt, 'hex'),
            iterations,
            32,
            algorithm
        ).toString('hex');

        if (!metadata) {
            this.saveMetadata({ salt, iterations, algorithm });
        }

        return derivedKey;
    }

    private saveMetadata(metadata: KeyMetadata): void {
        try {
            fs.writeFileSync(this.metadataPath, JSON.stringify(metadata, null, 2));
            this.logger.debug(`Saved metadata to ${this.metadataPath}`);
        } catch (error) {
            this.logger.error('Failed to save metadata', { error });
            throw error;
        }
    }

    private loadMetadata(): KeyMetadata | null {
        try {
            if (fs.existsSync(this.metadataPath)) {
                const data = fs.readFileSync(this.metadataPath, 'utf8');
                this.logger.debug(`Loaded metadata from ${this.metadataPath}`);
                return JSON.parse(data);
            }
        } catch (error) {
            this.logger.warn('Failed to load metadata', { error });
        }
        return null;
    }

    createContainer(sizeMB: number = 1024): void {
        this.logger.info(`Creating encrypted container: ${this.containerPath} (${sizeMB}MB)`);

        try {
            execSync(`fallocate -l ${sizeMB}M ${this.containerPath}`);
            this.logger.debug('Container file allocated.');

            this.logger.debug('Formatting with LUKS...');
            const formatResult = spawnSync(
                'cryptsetup',
                ['luksFormat', this.containerPath, '--batch-mode', '--key-file=-'],
                { input: this.key }
            );

            if (formatResult.status !== 0) {
                throw new Error(`LUKS format failed: ${formatResult.stderr?.toString()}`);
            }

            this.logger.debug(`Opening LUKS container with mapper name: ${this.mapperName}`);
            const openResult = spawnSync(
                'cryptsetup',
                ['open', this.containerPath, this.mapperName, '--key-file=-'],
                { input: this.key }
            );

            if (openResult.status !== 0) {
                throw new Error(`LUKS open failed: ${openResult.stderr?.toString()}`);
            }

            this.logger.debug('Creating ext4 filesystem...');
            execSync(`sudo mkfs.ext4 /dev/mapper/${this.mapperName}`);

            this.logger.debug(`Mounting to: ${this.mountPath}`);
            execSync(`sudo mount /dev/mapper/${this.mapperName} ${this.mountPath}`);

            execSync(`sudo chown -R $USER:$USER ${this.mountPath}`);

            this.isUnlocked = true;
            this.logger.info('Encrypted folder created and mounted successfully.');
        } catch (error) {
            this.logger.error('Failed to create container', { error });
            this.cleanup();
            throw error;
        }
    }
    private ensureMapperNotExists(): void {
        try {
            const mapperPath = `/dev/mapper/${this.mapperName}`;
            if (fs.existsSync(mapperPath)) {
                this.logger.warn(`Mapper ${this.mapperName} already exists. Closing first...`);
                try {
                    execSync(`sudo cryptsetup close ${this.mapperName}`);
                    this.logger.info(`Existing mapper ${this.mapperName} closed.`);
                } catch (err) {
                    this.logger.error(`Failed to close existing mapper ${this.mapperName}`, { err });
                    throw err;
                }
            }
        } catch (err) {
            this.logger.error('Error checking mapper existence', { err });
            throw err;
        }
    }
    unlock(): void {
        this.logger.info(`Unlocking encrypted container: ${this.containerPath}`);

        try {
            if (this.isUnlocked) {
                this.logger.warn('Container is already unlocked.');
                return;
            }

            if (!fs.existsSync(this.containerPath)) {
                throw new Error(`Container not found: ${this.containerPath}`);
            }

            // ✅ Ensure mapper doesn’t already exist
            this.ensureMapperNotExists();

            this.logger.debug(`Opening LUKS container with mapper name: ${this.mapperName}`);
            const openResult = spawnSync(
                'cryptsetup',
                ['open', this.containerPath, this.mapperName, '--key-file=-'],
                { input: this.key }
            );

            if (openResult.status !== 0) {
                throw new Error(`Failed to open LUKS container: ${openResult.stderr?.toString()}`);
            }

            this.logger.debug(`Mounting to: ${this.mountPath}`);
            execSync(`sudo mount /dev/mapper/${this.mapperName} ${this.mountPath}`);

            this.isUnlocked = true;
            this.logger.info('Encrypted folder unlocked and mounted successfully.');
        } catch (error) {
            this.logger.error('Failed to unlock container', { error });
            this.cleanup();
            throw error;
        }
    }

    close(): void {
        this.logger.info('Closing encrypted container...');

        try {
            if (this.isUnlocked) {
                this.logger.debug(`Unmounting: ${this.mountPath}`);
                try {
                    execSync(`sudo umount ${this.mountPath}`);
                } catch (error) {
                    this.logger.warn('Unmount failed, may already be unmounted', { error });
                }

                this.logger.debug(`Closing LUKS mapper: ${this.mapperName}`);
                try {
                    execSync(`sudo cryptsetup close ${this.mapperName}`);
                } catch (error) {
                    this.logger.warn('Close failed, may already be closed', { error });
                }

                this.isUnlocked = false;
            }

            this.logger.info('Encrypted folder closed successfully.');
        } catch (error) {
            this.logger.error('Error during close', { error });
            throw error;
        }
    }

    cleanup(): void {
        this.logger.debug('Cleaning up resources...');

        if (this.isUnlocked) {
            try {
                this.close();
            } catch (error) {
                this.logger.error('Cleanup close failed', { error });
            }
        }

        this.key = '0'.repeat(this.key.length);
        this.logger.debug('Key zeroed.');
    }

    getMapperName(): string {
        return this.mapperName;
    }

    isContainerUnlocked(): boolean {
        return this.isUnlocked;
    }

    static fromPassword(
        containerPath: string,
        mountPath: string,
        password: string,
        logLevel?: string
    ): EncryptedFolder {
        const metadata = this.loadMetadataStatic(`${path.resolve(containerPath)}.meta`);
        const instance = new EncryptedFolder({
            containerPath,
            mountPath,
            logLevel
        });

        if (metadata) {
            instance.key = instance.deriveKeyFromPassword(password, metadata);
            instance.logger.info('Key derived from password using existing metadata.');
        } else {
            instance.key = instance.deriveKeyFromPassword(password);
            instance.logger.info('Key derived from password with new metadata.');
        }

        return instance;
    }

    private static loadMetadataStatic(metadataPath: string): KeyMetadata | null {
        try {
            if (fs.existsSync(metadataPath)) {
                const data = fs.readFileSync(metadataPath, 'utf8');
                return JSON.parse(data);
            }
        } catch {
            // Silent fail
        }
        return null;
    }
}