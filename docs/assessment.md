# Security Assessment of Encrypted LokiJS Database

## Overview
This project implements a local, password-protected encrypted database using LokiJS (v1.5.12) with a custom `EncryptedFsAdapter` for AES-256-GCM encryption on disk. It supports schema-validated collections (e.g., 'users') with versioning for entries and operations like `insert`, `update`, `delete`, `find`, and `unseal`. The database is stored in a single file (`database.db`) within a specified path, with all data encrypted at rest using a password-derived key.

The security design is robust for a basic local secret store, leveraging established cryptographic primitives to protect against casual disk access (e.g., stolen hard drive). However, it has limitations in access controls, performance under attack, and resistance to sophisticated threats like memory dumping or side-channel attacks. It is not suitable for high-security environments (e.g., multi-user systems or cloud storage) without additional hardening.

## Cryptographic Strengths
- **Encryption Algorithm**: AES-256-GCM provides confidentiality, integrity, and authenticity via its authentication tag, preventing tampering (e.g., modifying ciphertext).
- **Key Derivation**: PBKDF2 with SHA-256, 100,000 iterations, and a 16-byte salt resists brute-force attacks (e.g., rainbow tables or GPU-accelerated cracking). Random salt per file is correctly implemented.
- **IV and Tag Handling**: Uses 12-byte random IV (nonce) and 16-byte auth tag per encryption, following NIST recommendations for GCM to prevent IV reuse risks.
- **Fresh Encryption per Save**: Each `saveDatabase` call re-encrypts the entire database with new salt/IV/tag, providing forward secrecy for file contents.
- **Schema Validation**: AJV enforces data structure (e.g., requiring 'password' in secrets), preventing malformed data injection.
- **Versioning**: Updates require incrementing versions, preventing silent downgrades or overwrites. Deletes can target specific versions for auditability.

## Potential Vulnerabilities and Weaknesses
- **Password Management**:
    - Password stored in plaintext in memory (`this.password`). A process compromise (e.g., debugger, memory dump) exposes it, allowing full decryption.
    - Hardcoded password ('b1mujx22') in example is insecure for production. Weak passwords amplify brute-force risks despite PBKDF2.
    - No password rotation or multi-factor authentication support.

- **Access Controls and Overrides**:
    - **Readonly Override**: The `readonly` setting can be bypassed per-operation via `meta` (e.g., `{readonly: false}`). This weakens enforcement and could allow unauthorized writes if `meta` is attacker-controlled.
    - **Locked Flag Unused**: The `locked: true` setting is defined but not used, rendering it ineffective.
    - No role-based access or auditing. Operations assume caller has the password, with no change logging.

- **In-Memory Exposure**:
    - Entire database decrypted in memory via LokiJS. Secrets accessible via `unseal` without re-authentication. Process compromise exposes all data.
    - No secure memory handling (e.g., zeroing buffers), so decrypted data may linger in RAM or swap files.

- **File System Risks**:
    - User-specified path created if missing (`fs.mkdirSync`). Attacker-controlled paths could enable symlink attacks, overwriting sensitive files.
    - Single-file storage: Large databases degrade performance, and partial corruption risks total data loss (no sharding or backups).
    - No file integrity checks beyond GCM tag (e.g., no HMAC on entire file).
    - Relies on Node.js `fs` module, vulnerable to TOCTOU (time-of-check-to-time-of-use) races with concurrent access.

- **Error Handling and Side Channels**:
    - Errors leak details (e.g., "Key already exists" or schema validation errors), aiding probing attacks (e.g., username enumeration).
    - Timing attacks possible: Operations like `find` or `unseal` may have observable timing differences.
    - No rate limiting for brute-force attempts.

- **Dependencies and Implementation**:
    - LokiJS 1.5.12 is outdated; potential unpatched bugs in indexing or serialization.
    - AJV: Complex schemas could allow bypasses if misconfigured.
    - No input sanitization on keys/names, risking query issues or injection in LokiJS.
    - Asynchronous risks: `readyPromise` ensures initialization, but concurrent operations during load could race.
    - Example-specific: Explicit version 1 in inserts is fine but could allow collisions if defaults are misused.

- **Broader Threats**:
    - **Offline Attacks**: Stolen `database.db` allows offline password brute-forcing. Weak passwords (<10 chars) are feasible with GPUs.
    - **No Per-Entry Secrecy**: All entries re-encrypted together, so compromising one version exposes historical data.
    - **Not Quantum-Resistant**: AES-256 vulnerable to future quantum attacks (e.g., Grover’s algorithm).
    - **Platform Dependencies**: Node.js crypto (OpenSSL) inherits upstream vulnerabilities.

## Attack Scenarios
1. **Disk Theft**: Attacker obtains `database.db`. Data safe without password (assuming strong password).
2. **Process Compromise**: Attacker accesses running Node process, gaining decrypted DB and password.
3. **Code Injection**: Untrusted input to `insert`/`update` could exploit schema bypasses or overflow buffers.
4. **Downgrade Attack**: Prevented by versioning, but restored old files lack enforcement.
5. **Brute-Force**: Weak passwords (~8 chars) crackable in ~10^12 operations on GPU clusters.

## Recommendations for Improvement
- **Password Handling**:
    - Use environment variables or secure prompts, not hardcoded passwords.
    - Increase PBKDF2 iterations to 600,000+ (OWASP) or use Argon2.
    - Add password strength checks and rotation.

- **Access Controls**:
    - Make `readonly` non-overridable or require admin password for overrides.
    - Implement `locked` flag to block operations until unlocked.
    - Add per-collection ACLs or encryption keys.

- **In-Memory Security**:
    - Use `secure-memory` or `sodium` for secure buffers.
    - Encrypt secrets in memory or use short-lived sessions.
    - Run in sandboxed environment (e.g., Node VM module).

- **File and Operational Security**:
    - Check file permissions (e.g., chmod 600).
    - Support sharding or encrypted backups with versioning.
    - Log operations to a separate encrypted audit file.
    - Use generic error messages (e.g., "Operation failed").

- **Testing and Auditing**:
    - Fuzz inputs with Jest/fuzzers for crashes or leaks.
    - Use static analysis (ESLint-security, SonarQube).
    - Conduct cryptographic review of adapter.
    - Benchmark offline cracking with Hashcat.

- **Alternatives**:
    - For production, use Keyv with encryption or SQLite with SQLCipher.
    - For cloud, use AWS KMS for key management.

## To-Do List
- [ ] Replace hardcoded password with environment variable or secure prompt.
- [ ] Increase PBKDF2 iterations to 600,000 or switch to Argon2.
- [ ] Implement password strength validation and rotation mechanism.
- [ ] Fix `readonly` override by enforcing global setting or requiring admin password.
- [ ] Implement `locked` flag to require explicit unlocking.
- [ ] Add per-collection access control lists or separate encryption keys.
- [ ] Use `secure-memory` or `sodium` for in-memory secret handling.
- [ ] Encrypt individual secrets in memory or implement session timeouts.
- [ ] Run database in a Node VM sandbox for process isolation.
- [ ] Add file permission checks (e.g., chmod 600 on `database.db`).
- [ ] Implement database sharding or encrypted backups with versioning.
- [ ] Log all operations to a separate encrypted audit file.
- [ ] Replace specific error messages with generic ones to prevent info leaks.
- [ ] Fuzz test inputs using Jest or similar tools.
- [ ] Run static analysis with ESLint-security or SonarQube.
- [ ] Conduct a cryptographic review of `EncryptedFsAdapter`.
- [ ] Benchmark offline password cracking with Hashcat.
- [ ] Update LokiJS to the latest version and check for security patches.
- [ ] Sanitize input keys/names to prevent query issues.
- [ ] Evaluate Keyv or SQLite with SQLCipher for production use.
- [ ] Consider AWS KMS integration for cloud-based key management.

## Conclusion
This implementation is suitable for low-threat scenarios (e.g., personal secret store) but requires hardening for production use. The to-do list above prioritizes critical security fixes. For specific use cases, further analysis can refine these recommendations.