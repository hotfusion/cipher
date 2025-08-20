# Testing @hotfusion/cipher with Jest in TypeScript

## Overview

This document provides a test file (`cipher.test.ts`) for the `@hotfusion/cipher` library (or the previously described Cipher library), a TypeScript-based secrets management library for Node.js. The test file uses Jest, a popular testing framework, to verify key functionalities, including initialization, secret writing and reading, versioning, unlocking with Shamir shares, and input validation. The document includes the test file code, setup instructions for a TypeScript project with Jest, and steps to run the tests. The tests are designed to ensure the library’s reliability and security for small to medium-scale applications.

## Prerequisites

- **Node.js**: Version 14.x or later (recommended: 18.x or higher).
- **npm**: Version 6.x or later.
- **TypeScript**: Version 4.x or later.
- **Dependencies**: `@hotfusion/cipher`, `shamir-secret-sharing`, and Jest-related packages.
- **File System**: Write permissions for the vault file (`vault.json`), audit log (`audit.log`), and share files (`./shares`).
- **Operating System**: Linux, macOS, or Windows (Windows requires WSL2 for file permission compatibility).

## Setup Instructions

### 1. Initialize a Node.js Project
1. Create a project directory:
   ```bash
   mkdir cipher-test-project
   cd cipher-test-project
   ```
2. Initialize a Node.js project:
   ```bash
   npm init -y
   ```

### 2. Install Dependencies
1. Install `@hotfusion/cipher` and required dependencies:
   ```bash
   npm install @hotfusion/cipher shamir-secret-sharing
   ```
2. Install Jest, TypeScript, and type definitions for testing:
   ```bash
   npm install --save-dev jest @types/jest ts-jest typescript @types/node
   ```
3. Verify `package.json`:
   ```json
   {
     "dependencies": {
       "@hotfusion/cipher": "^1.0.0",
       "shamir-secret-sharing": "^1.0.1"
     },
     "devDependencies": {
       "jest": "^29.7.0",
       "@types/jest": "^29.5.12",
       "ts-jest": "^29.1.2",
       "typescript": "^4.9.5",
       "@types/node": "^18.15.11"
     }
   }
   ```
   *Note*: Version numbers may vary.

### 3. Configure TypeScript
1. Create a `tsconfig.json` file:
   ```bash
   npx tsc --init
   ```
2. Update `tsconfig.json`:
   ```json
   {
     "compilerOptions": {
       "target": "ES2018",
       "module": "commonjs",
       "strict": true,
       "esModuleInterop": true,
       "outDir": "./dist",
       "rootDir": "./src",
       "moduleResolution": "node"
     },
     "include": ["src/**/*"],
     "exclude": ["node_modules"]
   }
   ```

### 4. Configure Jest
1. Create a Jest configuration file (`jest.config.js`):
   ```javascript
   module.exports = {
     preset: 'ts-jest',
     testEnvironment: 'node',
     testMatch: ['**/*.test.ts'],
     moduleFileExtensions: ['ts', 'js'],
     setupFilesAfterEnv: ['<rootDir>/src/setupTests.ts']
   };
   ```
2. Create a setup file (`src/setupTests.ts`) to clean up files before/after tests:
   ```typescript
   import * as fs from 'fs';
   import * as path from 'path';

   const filesToDelete = ['vault.json', 'audit.log', 'shares'];

   beforeEach(() => {
     filesToDelete.forEach(file => {
       const filePath = path.join(__dirname, file);
       if (fs.existsSync(filePath)) {
         if (fs.lstatSync(filePath).isDirectory()) {
           fs.rmSync(filePath, { recursive: true });
         } else {
           fs.unlinkSync(filePath);
         }
       }
     });
   });

   afterEach(() => {
     filesToDelete.forEach(file => {
       const filePath = path.join(__dirname, file);
       if (fs.existsSync(filePath)) {
         if (fs.lstatSync(filePath).isDirectory()) {
           fs.rmSync(filePath, { recursive: true });
         } else {
           fs.unlinkSync(filePath);
         }
       }
     });
   });
   ```

### 5. Create the Test File
Create the test file at `src/cipher.test.ts`:

```typescript
import { Cipher } from '@hotfusion/cipher';
import * as fs from 'fs';
import * as path from 'path';

describe('Cipher Library Tests', () => {
  let cipher: Cipher;
  const config = {
    numShares: 5,
    threshold: 3,
    persistent: true,
    filePath: path.join(__dirname, 'vault.json'),
    autoSaveInterval: 1000,
    password: 'test-password-2025',
    auditLogPath: path.join(__dirname, 'audit.log'),
  };

  beforeEach(async () => {
    cipher = new Cipher(config);
    if (!cipher['secrets']['ENCRYPTED_SEK']) {
      await cipher.init();
      cipher.saveShares(path.join(__dirname, 'shares'));
    }
  });

  test('should initialize and save shares', () => {
    const sharesDir = path.join(__dirname, 'shares');
    expect(fs.existsSync(sharesDir)).toBe(true);
    expect(fs.readdirSync(sharesDir).length).toBe(5); // 5 shares
  });

  test('should unlock vault with valid shares and password', async () => {
    const shares = [
      fs.readFileSync(path.join(__dirname, 'shares/share_1.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_2.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_3.txt'), 'utf8'),
    ];
    await expect(cipher.unlock(shares, 'test-password-2025')).resolves.toBeUndefined();
    expect(cipher['locked']).toBe(false);
  });

  test('should fail to unlock with insufficient shares', async () => {
    const shares = [
      fs.readFileSync(path.join(__dirname, 'shares/share_1.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_2.txt'), 'utf8'),
    ];
    await expect(cipher.unlock(shares, 'test-password-2025')).rejects.toThrow('Need at least 3 shares to unlock');
  });

  test('should fail to unlock with incorrect password', async () => {
    const shares = [
      fs.readFileSync(path.join(__dirname, 'shares/share_1.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_2.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_3.txt'), 'utf8'),
    ];
    await expect(cipher.unlock(shares, 'wrong-password')).rejects.toThrow('Invalid password');
  });

  test('should write and read a secret with versioning', async () => {
    const shares = [
      fs.readFileSync(path.join(__dirname, 'shares/share_1.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_2.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_3.txt'), 'utf8'),
    ];
    await cipher.unlock(shares, 'test-password-2025');

    cipher.write('secret/api-key', 'my-api-key-123', 'v1');
    expect(cipher.read('secret/api-key', 'v1')).toBe('my-api-key-123');

    cipher.write('secret/api-key', 'my-api-key-456', 'v2');
    expect(cipher.read('secret/api-key', 'v2')).toBe('my-api-key-456');
    expect(cipher.read('secret/api-key')).toBe('my-api-key-456'); // Latest version
  });

  test('should fail to write with invalid key or data', async () => {
    const shares = [
      fs.readFileSync(path.join(__dirname, 'shares/share_1.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_2.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_3.txt'), 'utf8'),
    ];
    await cipher.unlock(shares, 'test-password-2025');

    expect(() => cipher.write('', 'data')).toThrow('Key must be a non-empty string');
    expect(() => cipher.write('secret/key', null as any)).toThrow('Data must be a string');
  });

  test('should rotate master key and maintain secret access', async () => {
    const shares = [
      fs.readFileSync(path.join(__dirname, 'shares/share_1.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_2.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_3.txt'), 'utf8'),
    ];
    await cipher.unlock(shares, 'test-password-2025');

    cipher.write('secret/api-key', 'my-api-key-123', 'v1');
    const newShares = await cipher.rotateMasterKey();
    cipher.lock();

    await cipher.unlock(newShares.slice(0, 3), 'test-password-2025');
    expect(cipher.read('secret/api-key', 'v1')).toBe('my-api-key-123');
  });

  test('should persist and restore secrets', async () => {
    const shares = [
      fs.readFileSync(path.join(__dirname, 'shares/share_1.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_2.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_3.txt'), 'utf8'),
    ];
    await cipher.unlock(shares, 'test-password-2025');

    cipher.write('secret/api-key', 'my-api-key-123', 'v1');
    cipher.flush();

    const newCipher = new Cipher(config);
    await newCipher.unlock(shares, 'test-password-2025');
    expect(newCipher.read('secret/api-key', 'v1')).toBe('my-api-key-123');
  });

  test('should log operations to audit log', async () => {
    const shares = [
      fs.readFileSync(path.join(__dirname, 'shares/share_1.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_2.txt'), 'utf8'),
      fs.readFileSync(path.join(__dirname, 'shares/share_3.txt'), 'utf8'),
    ];
    await cipher.unlock(shares, 'test-password-2025');

    cipher.write('secret/api-key', 'my-api-key-123', 'v1');
    cipher.read('secret/api-key', 'v1');

    const auditLog = fs.readFileSync(config.auditLogPath, 'utf8');
    expect(auditLog).toContain('write');
    expect(auditLog).toContain('read');
  });
});
```

### 6. Add Test Script to package.json
Update `package.json` to include a test script:
```json
{
  "scripts": {
    "test": "jest"
  }
}
```

### 7. Run the Tests
1. Run the tests:
   ```bash
   npm test
   ```
2. Expected output:
   ```
   PASS  src/cipher.test.ts
   Cipher Library Tests
     ✓ should initialize and save shares (XXms)
     ✓ should unlock vault with valid shares and password (XXms)
     ✓ should fail to unlock with insufficient shares (XXms)
     ✓ should fail to unlock with incorrect password (XXms)
     ✓ should write and read a secret with versioning (XXms)
     ✓ should fail to write with invalid key or data (XXms)
     ✓ should rotate master key and maintain secret access (XXms)
     ✓ should persist and restore secrets (XXms)
     ✓ should log operations to audit log (XXms)
   ```

### 8. Troubleshooting
- **Module Not Found**: Ensure `@hotfusion/cipher` and dependencies are installed (`npm install`).
- **File Permission Errors**: Verify write permissions for `vault.json`, `audit.log`, and `shares`. Use `chmod 600` on Unix-like systems.
- **Test Failures**: Check that `cipher.test.ts` matches the Cipher library’s API. Adjust import paths or method names if `@hotfusion/cipher` differs.
- **TypeScript Errors**: Ensure `tsconfig.json` is configured and TypeScript is installed.
- **Jest Configuration**: If tests don’t run, verify `jest.config.js` and install `ts-jest` (`npm install ts-jest`).

## Test Coverage
The test file covers:
- **Initialization**: Verifies vault initialization and share generation.
- **Unlocking**: Tests successful and failed unlock attempts (insufficient shares, wrong password).
- **Write/Read**: Validates secret writing/reading with versioning, including latest version retrieval.
- **Input Validation**: Ensures errors are thrown for invalid keys and data.
- **Key Rotation**: Confirms secrets remain accessible after rotating the master key.
- **Persistence**: Tests saving and restoring secrets from the vault file.
- **Auditing**: Verifies operations are logged to the audit file.

## Security Considerations
- **Clean Up**: The `setupTests.ts` file deletes test files to prevent stale data, but ensure sensitive data (e.g., shares) is not left in production environments.
- **Password Strength**: Use strong passwords in tests (`test-password-2025` is for demo; use complex passwords in production).
- **File Security**: Ensure test files (`vault.json`, `audit.log`) are protected with restrictive permissions (e.g., `chmod 600`).

## Conclusion
The provided test file (`cipher.test.ts`) comprehensively tests the `@hotfusion/cipher` library’s core functionalities using Jest in a TypeScript environment. It verifies initialization, unlocking, secret management, versioning, input validation, key rotation, persistence, and auditing, ensuring the library operates reliably and securely. The setup is straightforward, requiring Node.js, TypeScript, Jest, and the library’s dependencies. For production use, enhance tests with additional edge cases (e.g., large secret volumes, HTTPS server testing) or integrate with CI/CD pipelines. If `@hotfusion/cipher` has specific differences from the assumed Cipher library, adjust the test file to match its API.