# Secure End-to-End Encrypted File Storage System

A cryptographically secure file storage system built in Go with end-to-end encryption, integrity verification, and secure file sharing. All cryptographic operations occur client-side against an untrusted server, ensuring complete data confidentiality.

<img width="750" height="750" alt="file_sharing" src="https://github.com/user-attachments/assets/20fe53d8-8058-420f-bacc-966759564d1c" />


## Features

### User Management
- Password-based authentication with Argon2 key derivation
- Deterministic UUID generation from usernames
- RSA key pairs for encryption and digital signatures
- Non-persistent session management

### File Operations
- **Store/Load**: Encrypt and decrypt files with automatic integrity protection
- **Append**: Efficiently append to files using linked-list block storage (O(1) complexity)
- **Integrity**: HMAC-SHA512 verification on all data blocks

### Secure Sharing
- **Invitation System**: Share files via cryptographic invitations using hybrid encryption (RSA + AES)
- **Namespace Isolation**: Recipients access shared files under custom filenames
- **Revocation**: Owners can revoke all access by rotating encryption keys

## Architecture

### Data Structures

#### User (In-Memory)
Username, root key, file access map

#### UserMetadata (Persistent, Encrypted)
Private keys, file access mappings

#### FileMetadata (Encrypted)
Owner, encryption/HMAC keys, shared users, version history

#### FileContent (Encrypted Blocks)
Encrypted data, HMAC, pointer to next block

### Cryptographic Design

