# Installation Instructions for @hotfusion/cipher

## Overview

The `@hotfusion/cipher` package is assumed to be a TypeScript-based secrets management library for Node.js, providing secure storage of secrets using AES-256-GCM encryption, Shamir’s Secret Sharing, and features like versioning, auditing, and an optional HTTPS server. This document provides step-by-step instructions to install and set up `@hotfusion/cipher` in a Node.js environment, including prerequisites, installation via npm, and initial configuration. These instructions are designed for developers working on small to medium-scale applications requiring secure secrets management.

## Prerequisites

Before installing `@hotfusion/cipher`, ensure the following requirements are met:

- **Node.js**: Version 14.x or later (recommended: 18.x or higher for optimal performance and security).
- **npm**: Version 6.x or later (bundled with Node.js).
- **TypeScript**: Version 4.x or later (if using TypeScript; optional for JavaScript projects).
- **Operating System**: Linux, macOS, or Windows (Windows requires WSL2 for full compatibility with file permissions).
- **Dependencies**: The package relies on `shamir-secret-sharing` and `express` for core functionality and the optional HTTPS server.
- **TLS Certificates** (optional): Required for the HTTPS server; can be self-signed for testing or obtained from a trusted CA for production.
- **File System Access**: Write permissions for the directory where the vault file (`vault.json`), audit log, and shares will be stored.

## Installation Steps

### 1. Install Node.js and npm
1. Download and install Node.js from [nodejs.org](https://nodejs.org/). Choose the LTS version (e.g., 18.x or 20.x).
2. Verify installation:
   ```bash
   node --version
   npm --version
   ```
   Example output:
   ```
   v18.17.1
   9.6.7
   ```

### 2. Set Up a Node.js Project
1. Create a new project directory:
   ```bash
   mkdir my-cipher-project
   cd my-cipher-project
   ```
2. Initialize a Node.js project:
   ```bash
   npm init -y
   ```
   This creates a `package.json` file.

### 3. Install @hotfusion/cipher
1. Install the `@hotfusion/cipher` package and its dependencies:
   ```bash
   npm install @hotfusion/cipher shamir-secret-sharing express
   ```
    - `@hotfusion/cipher`: The main secrets management library.
    - `shamir-secret-sharing`: For splitting and combining the master key.
    - `express`: For the optional HTTPS server.
2. If using TypeScript, install TypeScript and type definitions:
   ```bash
   npm install --save-dev typescript @types/node @types/express
   ```
3. Verify installation by checking `package.json`:
   ```json
   {
     "dependencies": {
       "@hotfusion/cipher": "^1.0.0",
       "shamir-secret-sharing": "^1.0.1",
       "express": "^4.18.2"
     },
     "devDependencies": {
       "typescript": "^4.9.5",
       "@types/node": "^18.15.11",
       "@types/express": "^4.17.17"
     }
   }
   ```
   *Note*: Version numbers may vary; the above are illustrative.

### 4. Configure TypeScript (Optional)
If using TypeScript:
1. Create a `tsconfig.json` file:
   ```bash
   npx tsc --init
   ```
2. Update `tsconfig.json` with recommended settings:
   ```json
   {
     "compilerOptions": {
       "target": "ES2018",
       "module": "commonjs",
       "strict": true,
       "esModuleInterop": true,
       "outDir": "./dist",
       "rootDir": "./src"
     }
   }
   ```
3. Create a `src` directory for TypeScript files:
   ```bash
   mkdir src
   ```

### 5. Generate TLS Certificates (Optional)
For the HTTPS server (required for production):
1. Generate self-signed certificates for testing:
   ```bash
   openssl req -new -x509 -days 365 -nodes -out server.crt -keyout server.key
   ```
    - Follow prompts to fill in certificate details (e.g., country, organization).
    - Outputs `server.crt` and `server.key` in the current directory.
2. For production, obtain certificates from a trusted CA (e.g., Let’s Encrypt) and place them in your project directory.

### 6. Basic Setup and Test
1. Create a test script to initialize and use Cipher:
    - Save as `src/index.ts` (TypeScript) or `index.js` (JavaScript):
   ```typescript
   import { Cipher } from '@hotfusion/cipher';
   import * as fs from 'fs';

   (async () => {
     // Initialize Cipher
     const cipher = new Cipher({
       numShares: 5,
       threshold: 3,
       persistent: true,
       filePath: './vault.json',
       autoSaveInterval: 5000,
       password: 'secure-password-2025',
       auditLogPath: './audit.log',
       tlsCertPath: './server.crt',
       tlsKeyPath: './server.key',
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

     // Write and read a secret
     cipher.write('secret/api-key', 'my-api-key-123', 'v1');
     console.log('Secret written.');
     console.log('Read secret:', cipher.read('secret/api-key', 'v1'));

     // Start HTTPS server (optional)
     cipher.startServer();
     console.log('HTTPS server started at https://localhost:3000');

     // Stop server after 5 seconds
     setTimeout(() => {
       cipher.stopServer();
       cipher.lock();
       console.log('Server stopped, vault locked.');
     }, 5000);
   })();
   ```
2. Run the script:
    - For TypeScript:
      ```bash
      npx ts-node src/index.ts
      ```
    - For JavaScript:
      ```bash
      node index.js
      ```
3. Expected output:
   ```
   Vault initialized, shares saved to ./shares
   Vault unlocked.
   Secret written.
   Read secret: my-api-key-123
   HTTPS server started at https://localhost:3000
   Server stopped, vault locked.
   ```

### 7. File System Permissions
- Ensure the user running the Node.js process has write permissions for:
    - `./vault.json` (vault file)
    - `./audit.log` (audit log)
    - `./shares` (directory for share files)
- On Unix-like systems, Cipher sets the vault file permissions to `600` (owner read/write only). Verify with:
  ```bash
  ls -l vault.json
  ```
  Expected output: `-rw-------`

### 8. Testing the HTTPS Server (Optional)
- Use `curl` to test the server:
  ```bash
  curl -X POST https://localhost:3000/write -d '{"key":"secret/test","data":"test-data","version":"v1"}' -H "Content-Type: application/json" --insecure
  curl https://localhost:3000/read?key=secret/test&version=v1 --insecure
  ```
    - The `--insecure` flag is for self-signed certificates; remove it in production with trusted certificates.

## Troubleshooting

- **Module Not Found**: Ensure `@hotfusion/cipher`, `shamir-secret-sharing`, and `express` are installed (`npm install`).
- **Permission Errors**: Check file permissions for `vault.json`, `audit.log`, and `shares`. Run as a user with appropriate access or use `chmod 600`.
- **TLS Errors**: Verify `server.crt` and `server.key` exist and are valid. For production, use trusted CA certificates.
- **TypeScript Errors**: Ensure `tsconfig.json` is configured and TypeScript is installed (`npm install typescript`).
- **Unlock Errors**: Ensure at least `threshold` shares are provided and the password matches.

## Security Considerations
- **Secure Share Storage**: Store shares (`./shares/share_X.txt`) in a secure location (e.g., encrypted storage) and distribute them via secure channels.
- **Password Strength**: Use a strong password (e.g., 16+ characters, mixed case, numbers, symbols) to prevent brute-force attacks.
- **TLS Certificates**: Use trusted CA certificates in production to avoid man-in-the-middle attacks.
- **File System Security**: Harden the host OS (e.g., restrict user access, use SELinux) to protect the vault file.

## Conclusion

Installing `@hotfusion/cipher` is straightforward, requiring Node.js, npm, and a few dependencies (`shamir-secret-sharing`, `express`). The setup involves initializing a Node.js project, installing the package, configuring TypeScript (if used), generating TLS certificates for the HTTPS server, and testing with a basic script. The library’s input validation and file permission settings enhance security, but care must be taken with share distribution and password strength. These instructions enable developers to quickly set up `@hotfusion/cipher` for secure secrets management in small to medium-scale applications. For advanced use cases, consider integrating with a database backend or enterprise tools like HashiCorp Vault for larger-scale deployments.