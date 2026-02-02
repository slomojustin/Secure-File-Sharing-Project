Secure End-to-End Encrypted File Storage System
A cryptographically secure file storage system built in Go with end-to-end encryption, integrity verification, and secure file sharing. All cryptographic operations occur client-side against an untrusted server, ensuring complete data confidentiality.
<img width="1536" height="1024" alt="file_sharing" src="https://github.com/user-attachments/assets/8ad96843-56d1-468c-94e1-a0991131043d" />


Features
User Management
Password-based authentication with Argon2 key derivation

Deterministic UUID generation from usernames

RSA key pairs for encryption and digital signatures

Non-persistent session management

File Operations
Store/Load: Encrypt and decrypt files with automatic integrity protection

Append: Efficiently append to files using linked-list block storage (O(1) complexity)

Integrity: HMAC-SHA512 verification on all data blocks

Secure Sharing
Invitation System: Share files via cryptographic invitations using hybrid encryption (RSA + AES)

Namespace Isolation: Recipients access shared files under custom filenames

Revocation: Owners can revoke all access by rotating encryption keys

Architecture
Data Structures
User (In-Memory)
Username, root key, file access map

UserMetadata (Persistent, Encrypted)
Private keys, file access mappings

FileMetadata (Encrypted)
Owner, encryption/HMAC keys, shared users, version history

FileContent (Encrypted Blocks)
Encrypted data, HMAC, pointer to next block

Cryptographic Design
text
Password + Salt → [Argon2] → Root Key
                              ↓
                   [HashKDF] → Encryption Key
                   [HashKDF] → HMAC Key
Storage Format
User: [Salt || HMAC || Encrypted UserMetadata]

File Metadata: [HMAC || Encrypted FileMetadata]

Invitation: [Encrypted Symmetric Key || Encrypted AccessNode]

API
User Operations
InitUser(username, password)
Creates account with key generation

GetUser(username, password)
Authenticates and loads user session

File Operations
StoreFile(filename, content)
Encrypts and stores/overwrites file

LoadFile(filename)
Retrieves and decrypts file with integrity verification

AppendToFile(filename, content)
Appends data without rewriting existing blocks

Sharing Operations
CreateInvitation(filename, recipientUsername)
Generates encrypted invitation

AcceptInvitation(senderUsername, invitationPtr, filename)
Accepts shared file

RevokeAccess(filename, recipientUsername)
Revokes all sharing by key rotation

Security Properties
Confidentiality
AES-CTR encryption with random IVs

Separate encryption for content and metadata

Hybrid encryption for invitations

Integrity
HMAC-SHA512 on all encrypted data

Per-block verification

Tampering detection before decryption

Access Control
Owner-only revocation

Single-use invitations

Cryptographic revocation via key rotation

Implementation Highlights
Efficient Appends
Linked-list structure with LastBlockLoc tracking enables O(1) appends without traversing the file.

Filename Privacy
Filenames are hashed before storage to prevent enumeration attacks.

Revocation Strategy
Deletes invitation UUIDs, rotates to new metadata UUID and encryption keys, invalidating all existing shares atomically.

Deterministic UUIDs
User UUIDs derived from username hashes enable consistent lookup without additional mappings.

Dependencies
github.com/cs161-staff/project2-userlib - Cryptographic primitives

github.com/google/uuid - UUID generation

encoding/json - Serialization

encoding/hex - Encoding utilities

Error Handling
Comprehensive error checking for:

Authentication failures

HMAC verification failures (tampering detected)

Missing files or corrupted metadata

Permission violations

Invalid invitations

Limitations
No key rotation for user root keys

Flat namespace (no directories)

Single ownership (no transfer)

Revocation affects all users (no selective revocation)
