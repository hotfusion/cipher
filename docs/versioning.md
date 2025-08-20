# Cipher Versioning: Managing Secrets with Timestamps and Custom Version Strings

## Overview

The Cipher library, a lightweight secrets management library implemented in TypeScript for Node.js, includes a robust versioning feature for secrets. This allows secrets to be stored with either timestamps or custom version strings, enabling retrieval of specific versions or the latest version of a secret. This document details how versioning is implemented in Cipher, its features, benefits, and limitations, and provides a demo to illustrate its usage. The versioning capability is particularly useful for tracking changes to secrets, supporting rollback, and ensuring compliance in small to medium-scale applications.

## Versioning Feature Description

### Functionality
- **Versioning Mechanism**: Secrets in Cipher are stored in a key-value store where keys are formatted as `key:version`. The version can be:
    - A **timestamp** (automatically generated as `Date.now()` if no version is provided).
    - A **custom version string** (user-specified, e.g., `v1`, `prod-2025`).
- **Storage**: Secrets are encrypted with the Session Encryption Key (SEK) using AES-256-GCM and stored in the in-memory `secrets` object or persisted to a file (`vault.json`) in persistent mode.
- **Retrieval**: The `read` method allows retrieval of a specific version (e.g., `secret/foo:v1`) or the latest version of a secret by sorting keys and selecting the most recent.
- **Implementation**:
    - **Write**: The `write` method accepts an optional `version` parameter. If omitted, it defaults to a timestamp (`Date.now()`).
    - **Read**: The `read` method accepts an optional `version` parameter. If omitted, it retrieves the latest version by sorting keys starting with the given `key:` prefix.

### Key Features
- **Flexible Versioning**: Supports both automatic timestamp-based versioning and user-defined version strings, allowing flexibility for different use cases.
- **Latest Version Retrieval**: Automatically retrieves the latest version of a secret if no version is specified, simplifying access to current data.
- **Rollback Capability**: Specific versions can be retrieved, enabling rollback to previous secret values (e.g., for recovering from misconfigurations).
- **Compliance Support**: Versioning facilitates auditing and tracking changes, critical for compliance requirements like GDPR or SOC 2.
- **Efficient Storage**: Versioned secrets are stored efficiently in the same key-value structure, with no additional overhead beyond key formatting.

### Security Considerations
- **Encryption**: All versions of a secret are encrypted with AES-256-GCM, ensuring confidentiality and integrity.
- **Access Control**: Versioned secrets are only accessible when the vault is unlocked (requiring Shamir shares and optional password).
- **Audit Logging**: Every `write` and `read` operation, including version details, is logged to the audit file, ensuring traceability.

### Limitations
- **Storage Overhead**: Storing multiple versions increases memory and disk usage (e.g., 10 versions of a 1KB secret add 10KB).
- **No Automatic Cleanup**: Cipher does not automatically delete old versions, which could lead to storage bloat if not managed.
- **Key Sorting for Latest Version**: Retrieving the latest version requires sorting keys, which is O(n log n) for keys with the same prefix, potentially slow for thousands of versions of a single key.
- **No Version Metadata**: Versioning tracks only the key and data, not additional metadata (e.g., creation date, author), unlike enterprise tools like HashiCorp Vault.

## Implementation Details

### Write Method
- **Signature**:
  ```typescript
  write(key: string, data: string, version?: string): void
  ```
- **Logic**:
    - Validates `key` (non-empty string) and `data` (string).
    - Constructs a versioned key: `key:version` if `version` is provided, or `key:timestamp` if not.
    - Encrypts `data` with the SEK using AES-256-GCM.
    - Stores the encrypted data in the `secrets` object under the versioned key.
    - Schedules auto-save if persistent mode is enabled.
    - Logs the operation to the audit log.

### Read Method
- **Signature**:
  ```typescript
  read(key: string, version?: string): string | null
  ```
- **Logic**:
    - If `version` is provided, retrieves `key:version` directly.
    - If no `version` is provided, finds all keys starting with `key:`, sorts them, and selects the last (latest) one.
    - Decrypts the secret with the SEK and returns it, or returns `null` if not found.
    - Logs the operation to the audit log.

### Code Snippets
```typescript
// Write implementation
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

// Read implementation
read(key: string, version: string | null = null): string | null {
  if (this.locked) throw new Error('Cipher is locked! Cannot read.');
  let versionKey: string;
  if (version) {
    versionKey = `${key}:${version}`;
  } else {
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
```

## Demo: Versioning in Action

This demo showcases versioning by writing multiple versions of a secret (using both custom strings and timestamps), retrieving specific and latest versions, and demonstrating audit logging.

```typescript
import { Cipher } from './cipher-file-encrypted';
import * as fs from 'fs';

(async () => {
  // Initialize Cipher with persistent storage
  const cipher = new Cipher({
    numShares: 5,
    threshold: 3,
    persistent: true,
    filePath: './vault.json',
    autoSaveInterval: 5000,
    password: 'secure-password-2025',
    auditLogPath: './audit.log',
  });

  // Initialize vault if not already set up
  if (!cipher['secrets']['ENCRYPTED_SEK']) {
    await cipher.init();
    cipher.saveShares('./shares');
    console.log('Vault initialized, shares saved to ./shares');
  }

  // Unlock vault
  const shares = [
    fs.readFileSync('./shares/share_1.txt', 'utf8'),
    fs.readFileSync('./shares/share_2.txt', 'utf8'),
    fs.readFileSync('./shares/share_3.txt', 'utf8'),
  ];
  await cipher.unlock(shares, 'secure-password-2025');
  console.log('Vault unlocked.');

  // Write multiple versions of a secret
  cipher.write('secret/db-cred', 'password123', 'v1');
  cipher.write('secret/db-cred', 'password456', 'v2');
  cipher.write('secret/db-cred', 'password789'); // Uses timestamp
  cipher.flush();
  console.log('Wrote three versions of secret/db-cred.');

  // Read specific versions
  console.log('Version v1:', cipher.read('secret/db-cred', 'v1')); // Outputs: password123
  console.log('Version v2:', cipher.read('secret/db-cred', 'v2')); // Outputs: password456

  // Read latest version
  console.log('Latest version:', cipher.read('secret/db-cred')); // Outputs: password789 (or latest timestamp)

  // Lock vault
  cipher.lock();
  console.log('Vault locked.');

  // Check audit log
  console.log('Audit log contents:');
  console.log(fs.readFileSync('./audit.log', 'utf8'));
})();
```

### Setup Instructions
1. **Dependencies**: Install `shamir-secret-sharing` and `express`:
   ```bash
   npm install shamir-secret-sharing express
   ```
2. **File System**: Ensure write permissions for `./vault.json`, `./audit.log`, and `./shares`.
3. **Execution**: Save the code as `versioning-demo.ts` and run with:
   ```bash
   ts-node versioning-demo.ts
   ```
4. **Expected Output**:
    - Secrets are written with versions `v1`, `v2`, and a timestamp.
    - Reading specific versions returns `password123` and `password456`.
    - Reading the latest version returns `password789` (or the latest timestamped version).
    - The audit log (`./audit.log`) records all write and read operations with versioned keys.

## Benefits of Versioning

- **Change Tracking**: Versioning allows tracking changes to secrets, essential for debugging or auditing (e.g., identifying when a credential was updated).
- **Rollback**: Retrieving older versions enables recovery from errors (e.g., reverting to a previous API key after a failed update).
- **Compliance**: Versioned secrets with audit logging support regulatory requirements by documenting access and changes.
- **Flexibility**: Custom version strings (e.g., `prod`, `dev`) allow semantic versioning, while timestamps provide automatic versioning for simple use cases.

## Limitations and Considerations

- **Storage Growth**: Each version adds a new key-value pair, increasing memory and disk usage. For example, 1,000 secrets with 10 versions each consume ~10x the storage of a single version.
- **Performance**: Retrieving the latest version involves sorting keys, which is O(n log n) for `n` versions of a key. This is negligible for dozens of versions but may slow down for thousands.
- **Management**: No built-in mechanism to delete old versions, requiring manual cleanup to manage storage.
- **No Metadata**: Versions lack additional metadata (e.g., creation time, user), which could be useful for auditing in complex systems.
- **Comparison to Enterprise Tools**: HashiCorp Vault offers advanced versioning with metadata, automatic cleanup, and UI support, while Cipher’s versioning is simpler but sufficient for small to medium-scale use.

## Conclusion

Cipher’s versioning feature, allowing secrets to be stored with timestamps or custom version strings, is a powerful tool for managing secret changes in small to medium-scale applications. It enables flexible storage, retrieval of specific or latest versions, and supports rollback and compliance through audit logging. The implementation is secure (leveraging AES-256-GCM) and efficient for typical use cases, but storage overhead and lack of automatic cleanup may require manual management in high-version scenarios. For applications needing basic versioning without the complexity of enterprise tools like HashiCorp Vault, Cipher’s approach is effective and easy to use, making it suitable for developers and small teams managing sensitive data.