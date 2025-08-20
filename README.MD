# Cipher: Secure Secrets Management Library

## Overview

Cipher is a lightweight, secure secrets management library implemented in TypeScript for Node.js. It provides an in-memory key-value store for sensitive data, protected by AES-256-GCM encryption and Shamir's Secret Sharing for key distribution. It supports optional persistent storage to an encrypted file, with features like auto-saving, crash-safe flushing, key rotation, versioning, auditing, backups, and optional network access via an HTTPS server. This documentation covers all methods, their features, and includes demo code for each.

## Key Features

- **Shamir's Secret Sharing**: Splits the master key into shares using the `shamir-secret-sharing` library, requiring a threshold number of shares to reconstruct the key, ensuring secure distributed key management.
- **Multi-Layer Encryption**: Uses a 256-bit master key to encrypt a Session Encryption Key (SEK), which encrypts individual secrets using AES-256-GCM for confidentiality, integrity, and authenticity.
- **Locking Mechanism**: Explicit lock/unlock states to control access; keys are cleared from memory when locked to prevent unauthorized access.
- **Persistent Storage**: Optional encrypted vault file with auto-save, integrity checks (HMAC), and platform-specific paths (e.g., `~/.CipherDB/vault.json` on Linux).
- **Key Rotation**: Supports rotating the master key, generating new shares, and re-encrypting the vault.
- **Versioning**: Secrets can be versioned with timestamps or custom version strings, allowing retrieval of specific or latest versions.
- **Auditing**: Logs all operations (init, unlock, lock, read, write, etc.) to a file for monitoring and compliance.
- **Backup and Restore**: Save and restore the encrypted vault to/from backup files.
- **Input Validation**: Robust checks for constructor options, keys, and data to prevent misuse.
- **Crash Safety**: Hooks into process signals (SIGINT, SIGTERM, uncaught exceptions) to flush changes before exit.
- **Optional HTTPS Server**: Exposes API endpoints for remote access, requiring TLS certificates for security.
- **File Security**: Restrictive file permissions (e.g., 600 on Unix-like systems) and HMAC-based integrity checks for the vault file.

## Dependencies

- **Node.js built-ins**: `crypto`, `fs`, `path`, `os` for encryption, file handling, and platform-specific operations.
- **External**:
    - `shamir-secret-sharing`: For secure Shamir's Secret Sharing implementation.
    - `express` and `https`: For optional HTTPS server functionality.

Install dependencies:
```bash
npm install shamir-secret-sharing express
```

## Security Considerations

- **Share Distribution**: Shares are generated as hex strings and can be saved to files. Distribute securely (e.g., via encrypted channels) and never store all shares together.
- **Password Protection**: Optional password adds an extra authentication layer; use a strong password.
- **Key Rotation**: Rotate the master key periodically to mitigate risks of key compromise.
- **File Security**: The vault file is encrypted, but ensure the filesystem is secure (e.g., restrict access to the host machine).
- **Memory Safety**: Keys are cleared on lock, but unlocked keys in memory could be exposed via process dumps; use in trusted environments.
- **HTTPS Server**: Requires valid TLS certificates; do not use self-signed certificates in production.
- **Backup Safety**: Store backups securely to prevent unauthorized access to the encrypted vault.

## Constructor

### Description
Initializes a new Cipher instance with configurable options.

### Signature
```typescript
constructor(options: CipherOptions = {})
```

### Options (CipherOptions interface)
- `numShares?: number` (default: 5): Number of Shamir shares to generate.
- `threshold?: number` (default: 3): Minimum number of shares required to unlock.
- `persistent?: boolean` (default: false): Enable persistent storage to a file.
- `filePath?: string`: Custom path for the vault file; defaults to platform-specific location (e.g., `~/.CipherDB/vault.json`).
- `autoSaveInterval?: number` (default: 1000): Delay (ms) for auto-saving changes to disk.
- `password?: string`: Optional password for additional authentication.
- `auditLogPath?: string`: Custom path for audit log; defaults to same directory as vault file.
- `port?: number` (default: 3000): Port for the HTTPS server (if enabled).
- `tlsCertPath?: string`: Path to TLS certificate for HTTPS server.
- `tlsKeyPath?: string`: Path to TLS private key for HTTPS server.

### Features
- Validates `numShares >= threshold` and `threshold >= 1`.
- Sets up platform-specific default paths for persistent storage (e.g., `~/.CipherDB` on Linux/Mac, `%AppData%\CipherDB` on Windows).
- Initializes audit logging if persistent.
- Loads existing vault file if present.
- Registers crash-safe hooks for SIGINT, SIGTERM, and uncaught exceptions to flush changes.

### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';

const cipher = new Cipher({
  numShares: 5,
  threshold: 3,
  persistent: true,
  autoSaveInterval: 5000,
  password: 'secure-password',
  auditLogPath: './audit.log',
  port: 3000,
  tlsCertPath: './server.crt',
  tlsKeyPath: './server.key',
});

console.log('Cipher initialized with custom options.');
```

## Methods

### `init()`

#### Description
Initializes the Cipher by generating a master key and SEK, splitting the master key into shares, and encrypting the SEK. The vault starts in a locked state.

#### Signature
```typescript
async init(): Promise<void>
```

#### Features
- Generates 256-bit master key and SEK using `crypto.randomBytes`.
- Splits master key into `numShares` shares with `threshold` required for reconstruction using Shamir's Secret Sharing.
- Encrypts SEK with master key and stores it in the vault.
- Schedules auto-save if persistent.
- Logs operation to audit log.
- Outputs hex-encoded shares to console (distribute securely in production).

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';

(async () => {
  const cipher = new Cipher({ persistent: true });
  await cipher.init();
  // Shares are logged to console; save them securely
})();
```

### `saveShares(outputDir: string)`

#### Description
Saves Shamir shares to individual files in the specified directory.

#### Signature
```typescript
saveShares(outputDir: string): void
```

#### Features
- Creates output directory if it doesn't exist.
- Saves each share as a hex string in a file named `share_<index>.txt`.
- Useful for secure distribution or backup of shares.

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';

(async () => {
  const cipher = new Cipher({ numShares: 5, threshold: 3 });
  await cipher.init();
  cipher.saveShares('./shares');
  // Check ./shares for share_1.txt, share_2.txt, etc.
})();
```

### `unlock(providedShares: string[], password?: string)`

#### Description
Unlocks the Cipher by reconstructing the master key from provided shares and optional password, then decrypts the vault and loads the SEK.

#### Signature
```typescript
async unlock(providedShares: string[], password?: string): Promise<void>
```

#### Features
- Validates password (if set) by comparing SHA-256 hash.
- Requires at least `threshold` shares; converts hex shares to Uint8Array for Shamir reconstruction.
- Reconstructs master key using `shamir-secret-sharing`.
- Decrypts vault (if persistent) and verifies HMAC for integrity.
- Decrypts and loads SEK into memory.
- Sets `locked` to `false`.
- Logs operation to audit log.
- Throws errors for invalid password, insufficient shares, or tampered vault.

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';
import * as fs from 'fs';

(async () => {
  const cipher = new Cipher({ persistent: true, password: 'secure-password' });
  await cipher.init();
  // Example: read shares from files (in practice, obtain securely)
  const shares = [
    fs.readFileSync('./shares/share_1.txt', 'utf8'),
    fs.readFileSync('./shares/share_2.txt', 'utf8'),
    fs.readFileSync('./shares/share_3.txt', 'utf8'),
  ];
  await cipher.unlock(shares, 'secure-password');
  console.log('Vault unlocked.');
})();
```

### `lock()`

#### Description
Locks the Cipher, clearing the master key and SEK from memory.

#### Signature
```typescript
lock(): void
```

#### Features
- Sets `masterKey` and `sek` to `null`.
- Sets `locked` to `true`, preventing read/write operations.
- Logs operation to audit log.

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';
import * as fs from 'fs';

(async () => {
  const cipher = new Cipher({ persistent: true });
  await cipher.init();
  const shares = [
    fs.readFileSync('./shares/share_1.txt', 'utf8'),
    fs.readFileSync('./shares/share_2.txt', 'utf8'),
    fs.readFileSync('./shares/share_3.txt', 'utf8'),
  ];
  await cipher.unlock(shares);
  cipher.lock();
  console.log('Vault locked.');
})();
```

### `rotateMasterKey()`

#### Description
Rotates the master key, generates new shares, and re-encrypts the SEK and vault.

#### Signature
```typescript
async rotateMasterKey(): Promise<string[]>
```

#### Features
- Generates a new 256-bit master key.
- Creates new Shamir shares.
- Re-encrypts SEK with the new master key.
- Saves updated vault to disk if persistent.
- Returns new shares as hex strings for distribution.
- Logs operation to audit log.
- Requires vault to be unlocked.

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';
import * as fs from 'fs';

(async () => {
  const cipher = new Cipher({ persistent: true });
  await cipher.init();
  const shares = [
    fs.readFileSync('./shares/share_1.txt', 'utf8'),
    fs.readFileSync('./shares/share_2.txt', 'utf8'),
    fs.readFileSync('./shares/share_3.txt', 'utf8'),
  ];
  await cipher.unlock(shares);
  const newShares = await cipher.rotateMasterKey();
  console.log('New shares:', newShares);
  // Save new shares securely
})();
```

### `write(key: string, data: string, version?: string)`

#### Description
Writes an encrypted secret to the vault, optionally with a version.

#### Signature
```typescript
write(key: string, data: string, version?: string): void
```

#### Features
- Validates key (non-empty string) and data (string).
- Encrypts data with SEK using AES-256-GCM.
- Stores secret under `key:version` or `key:timestamp` if no version provided.
- Schedules auto-save if persistent.
- Logs operation to audit log.
- Requires vault to be unlocked.

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';
import * as fs from 'fs';

(async () => {
  const cipher = new Cipher({ persistent: true });
  await cipher.init();
  const shares = [
    fs.readFileSync('./shares/share_1.txt', 'utf8'),
    fs.readFileSync('./shares/share_2.txt', 'utf8'),
    fs.readFileSync('./shares/share_3.txt', 'utf8'),
  ];
  await cipher.unlock(shares);
  cipher.write('secret/foo', 'sensitive data', 'v1');
  console.log('Secret written.');
})();
```

### `read(key: string, version?: string)`

#### Description
Reads a secret from the vault, optionally by version.

#### Signature
```typescript
read(key: string, version?: string): string | null
```

#### Features
- Retrieves latest version if no version specified, or specific version if provided.
- Decrypts secret with SEK.
- Returns `null` if key/version not found.
- Logs operation to audit log.
- Requires vault to be unlocked.

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';
import * as fs from 'fs';

(async () => {
  const cipher = new Cipher({ persistent: true });
  await cipher.init();
  const shares = [
    fs.readFileSync('./shares/share_1.txt', 'utf8'),
    fs.readFileSync('./shares/share_2.txt', 'utf8'),
    fs.readFileSync('./shares/share_3.txt', 'utf8'),
  ];
  await cipher.unlock(shares);
  cipher.write('secret/foo', 'sensitive data', 'v1');
  const data = cipher.read('secret/foo', 'v1');
  console.log('Read data:', data); // Outputs: sensitive data
})();
```

### `flush()`

#### Description
Immediately saves the vault to disk, canceling any scheduled auto-save.

#### Signature
```typescript
flush(): void
```

#### Features
- Saves encrypted vault with HMAC for integrity.
- Sets restrictive file permissions (600 on Unix-like systems).
- No-op if not persistent.
- Logs operation to audit log (implicitly via `saveToFile`).

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';
import * as fs from 'fs';

(async () => {
  const cipher = new Cipher({ persistent: true });
  await cipher.init();
  const shares = [
    fs.readFileSync('./shares/share_1.txt', 'utf8'),
    fs.readFileSync('./shares/share_2.txt', 'utf8'),
    fs.readFileSync('./shares/share_3.txt', 'utf8'),
  ];
  await cipher.unlock(shares);
  cipher.write('secret/foo', 'sensitive data');
  cipher.flush();
  console.log('Vault flushed to disk.');
})();
```

### `saveToFile()`

#### Description
Saves the vault to the configured file path with encryption and integrity check. Typically called internally.

#### Signature
```typescript
saveToFile(): void
```

#### Features
- Serializes secrets to JSON, encrypts with master key, and adds HMAC.
- Sets file permissions to 600 (Unix-like systems).
- Requires master key to be present.
- Called by `flush` and auto-save.

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';
import * as fs from 'fs';

(async () => {
  const cipher = new Cipher({ persistent: true });
  await cipher.init();
  const shares = [
    fs.readFileSync('./shares/share_1.txt', 'utf8'),
    fs.readFileSync('./shares/share_2.txt', 'utf8'),
    fs.readFileSync('./shares/share_3.txt', 'utf8'),
  ];
  await cipher.unlock(shares);
  cipher.write('secret/foo', 'sensitive data');
  cipher['saveToFile'](); // Direct call for demo
  console.log('Vault saved to file.');
})();
```

### `logOperation(operation: string, details: Record<string, any>)`

#### Description
Logs an operation to the audit log file. Typically called internally.

#### Signature
```typescript
logOperation(operation: string, details: Record<string, any>): void
```

#### Features
- Appends timestamped log entry with operation name and details.
- No-op if audit log path not set (non-persistent mode).

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';

(async () => {
  const cipher = new Cipher({ persistent: true, auditLogPath: './audit.log' });
  await cipher.init();
  cipher['logOperation']('manual-log', { detail: 'test' });
  // Check ./audit.log for entry
})();
```

### `backup(backupPath: string)`

#### Description
Backs up the vault to a specified file path.

#### Signature
```typescript
backup(backupPath: string): void
```

#### Features
- Copies the current vault file to the specified path.
- Throws if vault file doesn't exist or not persistent.
- Logs operation to audit log.

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';
import * as fs from 'fs';

(async () => {
  const cipher = new Cipher({ persistent: true });
  await cipher.init();
  const shares = [
    fs.readFileSync('./shares/share_1.txt', 'utf8'),
    fs.readFileSync('./shares/share_2.txt', 'utf8'),
    fs.readFileSync('./shares/share_3.txt', 'utf8'),
  ];
  await cipher.unlock(shares);
  cipher.write('secret/foo', 'sensitive data');
  cipher.backup('./vault-backup.json');
  console.log('Vault backed up.');
})();
```

### `restore(backupPath: string)`

#### Description
Restores the vault from a backup file.

#### Signature
```typescript
restore(backupPath: string): void
```

#### Features
- Loads backup file into memory for decryption on next unlock.
- Throws if backup file doesn't exist.
- Logs operation to audit log.

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';
import * as fs from 'fs';

(async () => {
  const cipher = new Cipher({ persistent: true });
  await cipher.init();
  const shares = [
    fs.readFileSync('./shares/share_1.txt', 'utf8'),
    fs.readFileSync('./shares/share_2.txt', 'utf8'),
    fs.readFileSync('./shares/share_3.txt', 'utf8'),
  ];
  await cipher.unlock(shares);
  cipher.write('secret/foo', 'sensitive data');
  cipher.backup('./vault-backup.json');
  cipher.lock();
  cipher.restore('./vault-backup.json');
  await cipher.unlock(shares);
  console.log('Vault restored and unlocked.');
})();
```

### `startServer()`

#### Description
Starts an HTTPS server exposing API endpoints for remote access.

#### Signature
```typescript
startServer(): void
```

#### Features
- Exposes `/unlock`, `/lock`, `/write`, `/read` endpoints.
- Requires TLS certificate and key.
- Throws if TLS config missing.
- Supports JSON payloads for operations.

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';

(async () => {
  const cipher = new Cipher({
    persistent: true,
    tlsCertPath: './server.crt',
    tlsKeyPath: './server.key',
  });
  await cipher.init();
  cipher.startServer();
  // Access via curl, e.g.:
  // curl -X POST https://localhost:3000/write -d '{"key":"secret/foo","data":"sensitive data","version":"v1"}' -H "Content-Type: application/json"
})();
```

### `stopServer()`

#### Description
Stops the HTTPS server if running.

#### Signature
```typescript
stopServer(): void
```

#### Features
- Closes the server gracefully.
- No-op if server not running.

#### Demo
```typescript
import { Cipher } from './cipher-file-encrypted';

(async () => {
  const cipher = new Cipher({
    persistent: true,
    tlsCertPath: './server.crt',
    tlsKeyPath: './server.key',
  });
  await cipher.init();
  cipher.startServer();
  setTimeout(() => {
    cipher.stopServer();
    console.log('Server stopped.');
  }, 5000);
})();
```

## Full Demo

This combines all methods in a realistic workflow.

```typescript
import { Cipher } from './cipher-file-encrypted';
import * as fs from 'fs';

(async () => {
  // Initialize with persistent storage and password
  const cipher = new Cipher({
    numShares: 5,
    threshold: 3,
    persistent: true,
    password: 'secure-password',
    auditLogPath: './audit.log',
    tlsCertPath: './server.crt',
    tlsKeyPath: './server.key',
  });

  // Initialize vault
  if (!cipher['secrets']['ENCRYPTED_SEK']) {
    await cipher.init();
    cipher.saveShares('./shares');
  }

  // Unlock vault
  const shares = [
    fs.readFileSync('./shares/share_1.txt', 'utf8'),
    fs.readFileSync('./shares/share_2.txt', 'utf8'),
    fs.readFileSync('./shares/share_3.txt', 'utf8'),
  ];
  await cipher.unlock(shares, 'secure-password');

  // Write secrets with versioning
  cipher.write('secret/foo', 'sensitive data 1', 'v1');
  cipher.write('secret/foo', 'sensitive data 2', 'v2');

  // Read secrets
  console.log('Read v1:', cipher.read('secret/foo', 'v1')); // sensitive data 1
  console.log('Read latest:', cipher.read('secret/foo')); // sensitive data 2

  // Rotate master key
  const newShares = await cipher.rotateMasterKey();
  console.log('New shares:', newShares);

  // Backup vault
  cipher.backup('./vault-backup.json');

  // Restore from backup
  cipher.lock();
  cipher.restore('./vault-backup.json');
  await cipher.unlock(newShares.slice(0, 3), 'secure-password');

  // Start HTTPS server
  cipher.startServer();

  // Stop server after 5 seconds
  setTimeout(() => {
    cipher.stopServer();
    console.log('Server stopped.');
  }, 5000);

  // Flush and lock
  cipher.flush();
  cipher.lock();
})();
```

## Notes

- **Share Handling**: The demos use placeholder share files (`./shares/share_1.txt`). In practice, obtain shares securely and avoid hardcoding.
- **HTTPS Server**: Requires valid TLS certificates; generate with OpenSSL (`openssl req -new -x509 -days 365 -nodes -out server.crt -keyout server.key`) or use a trusted CA for production.
- **Audit Log**: Check `auditLogPath` (e.g., `./audit.log`) for operation logs.
- **Error Handling**: All methods throw descriptive errors for invalid inputs or states (e.g., locked vault, invalid shares).
- **Production Use**: Ensure secure share distribution, strong passwords, restricted file access, and valid TLS certificates.

This documentation provides a comprehensive guide to using the Cipher class, with demos illustrating each method's functionality. Copy this content into `CipherDocumentation.md` for use.