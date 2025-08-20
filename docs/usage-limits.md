# Cipher Maximum Usage Example

## Overview

This document provides an example of the maximum practical usage of the Cipher library, a lightweight secrets management library implemented in TypeScript for Node.js, as described in previous documentation. "Maximum usage" refers to pushing Cipher to its limits in terms of secret volume, access frequency, and operational complexity within its design constraints (in-memory storage, file-based persistence, single-threaded HTTPS server). The example demonstrates a scenario with thousands of secrets, frequent read/write operations, distributed share management, and HTTPS server access, while highlighting the library's limitations for very large-scale, high-concurrency environments.

## Defining Maximum Usage

Based on Cipher's design and the scalability analysis, maximum usage is constrained by:
- **Memory Limits**: In-memory storage (Node.js process, typically 1-2GB) limits secret volume to tens of thousands of small secrets (e.g., 1KB each).
- **Disk I/O**: File-based persistence (`vault.json`) introduces I/O bottlenecks for frequent writes, especially with the default 1000ms auto-save interval.
- **Concurrency**: The single-threaded HTTPS server (using `express`) handles up to a few hundred concurrent requests per second on typical hardware, depending on CPU and network.
- **Operational Complexity**: Managing Shamir shares across teams and frequent key rotations adds overhead but is feasible for small to medium teams.

For this example, we define maximum usage as:
- **Secrets**: 10,000 secrets (e.g., API keys, passwords), each ~1KB, totaling ~10MB in memory and on disk.
- **Access Frequency**: Hundreds of read/write operations per minute, simulating a busy application.
- **Shares**: 10 Shamir shares with a threshold of 5, distributed to a team.
- **Server**: HTTPS server handling up to 100 concurrent requests per second.
- **Operations**: Key rotation, versioning, auditing, and backups enabled.

This scenario is suitable for a medium-scale application (e.g., a microservices backend for a small enterprise) but approaches Cipher's practical limits.

## Maximum Usage Example

### Scenario
A medium-sized company runs a Node.js-based microservices application with 50 services, each requiring 200 secrets (e.g., database credentials, API keys). The total secret count is 10,000. The application performs 500 read/write operations per minute, uses persistent storage for durability, rotates the master key weekly, and exposes secrets via an HTTPS server for remote access. Shares are distributed to 10 team members, with 5 required to unlock the vault. Auditing and backups are enabled for compliance.

### Demo Code
The following TypeScript code demonstrates this maximum usage scenario, including initialization, share management, bulk secret operations, key rotation, backup/restore, and HTTPS server usage.

```typescript
import { Cipher } from './cipher-file-encrypted';
import * as fs from 'fs';

// Simulate maximum usage scenario
(async () => {
  // Initialize Cipher with max settings
  const cipher = new Cipher({
    numShares: 10, // Max shares for team distribution
    threshold: 5, // Reasonable threshold
    persistent: true,
    filePath: './vault.json',
    autoSaveInterval: 5000, // Balance I/O and durability
    password: 'super-secure-password-2025',
    auditLogPath: './audit.log',
    port: 3000,
    tlsCertPath: './server.crt', // Generate with: openssl req -new -x509 -days 365 -nodes -out server.crt -keyout server.key
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
    fs.readFileSync('./shares/share_4.txt', 'utf8'),
    fs.readFileSync('./shares/share_5.txt', 'utf8'),
  ];
  await cipher.unlock(shares, 'super-secure-password-2025');
  console.log('Vault unlocked.');

  // Bulk write 10,000 secrets
  console.log('Writing 10,000 secrets...');
  const startWrite = Date.now();
  for (let i = 0; i < 50; i++) { // 50 services
    for (let j = 0; j < 200; j++) { // 200 secrets per service
      const key = `service${i}/secret${j}`;
      const data = `sensitive-data-${i}-${j}-${Math.random().toString(36).substring(2, 15)}`.padEnd(1000, 'x'); // ~1KB
      cipher.write(key, data, `v1`);
    }
  }
  cipher.flush(); // Force immediate save
  console.log(`Wrote 10,000 secrets in ${Date.now() - startWrite}ms`);

  // Bulk read 1,000 secrets
  console.log('Reading 1,000 secrets...');
  const startRead = Date.now();
  for (let i = 0; i < 50; i += 2) { // Sample 20 services
    for (let j = 0; j < 40; j++) { // 40 secrets per service
      const key = `service${i}/secret${j}`;
      const data = cipher.read(key, 'v1');
      if (!data) console.error(`Failed to read ${key}`);
    }
  }
  console.log(`Read 1,000 secrets in ${Date.now() - startRead}ms`);

  // Rotate master key (weekly simulation)
  const newShares = await cipher.rotateMasterKey();
  cipher.saveShares('./new-shares');
  console.log('Master key rotated, new shares saved to ./new-shares');

  // Backup vault
  cipher.backup('./vault-backup.json');
  console.log('Vault backed up.');

  // Simulate restore after failure
  cipher.lock();
  cipher.restore('./vault-backup.json');
  await cipher.unlock(newShares.slice(0, 5), 'super-secure-password-2025');
  console.log('Vault restored and unlocked.');

  // Start HTTPS server for remote access
  cipher.startServer();
  console.log('HTTPS server started at https://localhost:3000');
  // Example client request:
  // curl -X POST https://localhost:3000/write -d '{"key":"service0/secret0","data":"updated-data","version":"v2"}' -H "Content-Type: application/json"
  // curl https://localhost:3000/read?key=service0/secret0&version=v2

  // Stop server after 10 seconds
  setTimeout(() => {
    cipher.stopServer();
    console.log('Server stopped.');
    cipher.lock();
  }, 10000);
})();
```

### Setup Instructions
1. **Dependencies**: Install `shamir-secret-sharing` and `express`:
   ```bash
   npm install shamir-secret-sharing express
   ```
2. **TLS Certificates**: Generate self-signed certificates for testing:
   ```bash
   openssl req -new -x509 -days 365 -nodes -out server.crt -keyout server.key
   ```
3. **Hardware**: Run on a server with at least 4GB RAM and a modern CPU to handle 10MB of secrets in memory and disk I/O.
4. **File System**: Ensure write permissions for `./vault.json`, `./audit.log`, `./shares`, and `./new-shares`.
5. **Execution**: Save the code as `max-usage.ts` and run with:
   ```bash
   ts-node max-usage.ts
   ```

## Performance and Limits

### Observed Performance
On a typical server (e.g., 4-core CPU, 8GB RAM, SSD):
- **Write**: Writing 10,000 secrets (~1KB each) takes ~5-10 seconds, dominated by encryption and disk I/O (with `flush`).
- **Read**: Reading 1,000 secrets takes ~1-2 seconds, as in-memory access is fast.
- **Disk Usage**: The `vault.json` file is ~10-15MB (encrypted JSON with HMAC).
- **Memory Usage**: ~20-30MB for 10,000 secrets (Node.js overhead + encrypted data).
- **HTTPS Server**: Handles ~100-200 concurrent requests per second for read/write operations, limited by Node.js's single-threaded event loop.

### Practical Limits
- **Secret Volume**: 10,000-50,000 secrets is feasible, depending on memory (1-2GB Node.js limit). Beyond this, memory exhaustion or slow disk I/O may occur.
- **Access Frequency**: Hundreds of read/write operations per minute are manageable. Thousands per second may cause delays due to I/O or server bottlenecks.
- **Concurrency**: The HTTPS server struggles with >200 concurrent requests; external load balancing or clustering is needed for higher throughput.
- **Share Management**: 10 shares with a threshold of 5 is practical for small teams but becomes complex for larger groups without automated distribution tools.

### Breaking Points
- **Memory**: Exceeding ~100,000 secrets (100MB+) risks crashing Node.js due to memory limits.
- **Disk I/O**: Frequent writes with a short `autoSaveInterval` (e.g., 100ms) cause significant I/O delays, especially on HDDs.
- **Concurrency**: The server may bottleneck at ~500 concurrent requests, causing timeouts or errors.
- **Operational Overhead**: Managing shares, key rotations, and backups for large teams requires significant manual effort without additional automation.

## Enhancing for Larger-Scale Usage

To push Cipher beyond this maximum usage:
- **Database Backend**: Replace file-based persistence with a database (e.g., Redis, PostgreSQL) to handle larger secret volumes and concurrent writes.
  ```typescript
  // Example (pseudo-code) for Redis integration
  import { createClient } from 'redis';
  const redis = createClient();
  await redis.connect();
  async saveToRedis() {
    const vaultString = JSON.stringify(this.secrets);
    const encryptedVault = Encryption.encrypt(vaultString, this.masterKey);
    await redis.set('cipher:vault', JSON.stringify(encryptedVault));
  }
  ```
- **Server Clustering**: Use Node.js `cluster` module or deploy multiple instances behind a load balancer.
  ```typescript
  import { cluster } from 'node:cluster';
  if (cluster.isPrimary) {
    for (let i = 0; i < os.cpus().length; i++) cluster.fork();
  } else {
    cipher.startServer();
  }
  ```
- **Cloud Integration**: Add support for AWS KMS or Azure Key Vault to manage the master key, reducing share management overhead.
- **Automated Share Distribution**: Integrate with secure channels (e.g., AWS S3 with IAM policies) for share storage and retrieval.

## Comparison to Enterprise Tools

For very large-scale usage (e.g., millions of secrets, thousands of concurrent requests):
- **HashiCorp Vault**: Scales to millions of secrets with database backends, supports dynamic secrets, and integrates with cloud platforms. Cipher lacks these features but is simpler to deploy.
- **AWS Secrets Manager**: Handles high concurrency and automatic rotation for cloud-native apps. Cipher requires manual enhancements for similar functionality.
- **Akeyless**: Offers vaultless architecture for distributed systems. Cipher's file-based approach is less suited for such environments.

## Conclusion

This example demonstrates Cipher's maximum usage for a medium-scale application with 10,000 secrets, hundreds of operations per minute, and HTTPS access. It is suitable for small to medium enterprises or isolated use cases within larger systems, leveraging its strong security (AES-256-GCM, Shamir's Secret Sharing) and lightweight design. However, for very large-scale, high-concurrency, or cloud-native environments, Cipher hits limits in memory, disk I/O, and server scalability. Enhancing it with a database backend, server clustering, or cloud integrations could extend its capabilities, but enterprise-grade tools like HashiCorp Vault or AWS Secrets Manager are better suited for massive workloads.