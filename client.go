package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/hex"
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

const RSAKeySizeBytes = 256

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).

type User struct {
	Username       string
	HashedPassword []byte
	Rootkey        []byte
	FileAccessMap  map[string]AccessInfo
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}
type Usermetadata struct {
	Username      string
	PrivateKey    []byte
	Files         map[string]string
	FileAccessMap map[string]AccessInfo
}

// has info about each file
type FileMetadata struct {
	OwnerID        string
	FileUUID       uuid.UUID
	EncryptionKey  []byte
	HMACKey        []byte
	SharedUsers    map[string][]byte
	VersionHistory []uuid.UUID
	NumBlocks      int
	LastBlockLoc   uuid.UUID
}

// stores actual data of files and points to next file
type FileContent struct {
	FileData      []byte
	HMAC          []byte
	NextBlockUUID *uuid.UUID
}

// this is what is stored in filemap that has info about metadata.
type AccessInfo struct {
	MetadataUUID uuid.UUID
	EncKey       []byte
	HMACKey      []byte
}

type Invitation struct {
	OwnerUsername string
	SharedToUser  string
	FileUUID      userlib.UUID
	EncKey        []byte
	HMACKey       []byte
}
type Append struct {
	ParentFileUUID userlib.UUID
	EncryptedChunk []byte
	HMAC           []byte
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	//1. Check if length of password or length of username is not empty
	//2. Derive UUID and see if it is already exists in datastore, return err if exists
	//3. Derive a root key with argon2 and the password
	//4. Derive other keys based off of the root key using HashKDF and generate
	// public and private key where public is stored in keystore and private in datastore
	//5. Create a User struct for information needed during the session
	//6. Create a Usermeatadata struct to store persistent info that is stored in Datastore
	//7. Encrypt and HMAC the data
	if len(username) == 0 {
		return nil, errors.New("username cannot be empty")
	}
	//step 1: Generate salt and root key
	salt := userlib.RandomBytes(16)
	rootKey := userlib.Argon2Key([]byte(password), salt, 16)

	//step 2: derive UUID
	hash := userlib.Hash([]byte(username))
	uuid, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(uuid)
	if ok {
		return nil, errors.New("user already exists")
	}

	//Step 3: Derive other keys
	pkEnc, skEnc, err := userlib.PKEKeyGen() //gens public and priv key
	if err != nil {
		return nil, err
	}
	signSk, signPk, err := userlib.DSKeyGen() //for digital signatures
	if err != nil {
		return nil, err
	}

	//storing in keystore
	err = userlib.KeystoreSet(username+"_enc", pkEnc) //storing public encryption key
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"_sign", signPk) //storing public digital sign
	if err != nil {
		return nil, err
	}

	//step 6: creating usermeata data and encrypting it
	type PrivateKeys struct {
		SKEnc  userlib.PKEDecKey
		SignSk userlib.DSSignKey
	}

	userMeta := Usermetadata{
		Username:      username,
		Files:         make(map[string]string),
		FileAccessMap: make(map[string]AccessInfo),
	}
	privateKeys := PrivateKeys{SKEnc: skEnc, SignSk: signSk} //use these to sign inivations or verify their identity or decrypt file keys sent to them via public-key encryption.
	privateKeyBytes, err := json.Marshal(privateKeys)
	if err != nil {
		return nil, err
	}
	userMeta.PrivateKey = privateKeyBytes

	userMetaBytes, err := json.Marshal(userMeta)
	if err != nil {
		return nil, err
	}
	//step 7: Encrypt the data and put a HMAC in it
	encryptKey, _ := userlib.HashKDF(rootKey, []byte("encrypt"))
	hmacKey, _ := userlib.HashKDF(rootKey, []byte("hmac"))
	encData := userlib.SymEnc(encryptKey[:16], userlib.RandomBytes(16), userMetaBytes)
	hmac, err := userlib.HMACEval(hmacKey[:16], encData)
	if err != nil {
		return nil, err
	}
	finalStore := append(salt, hmac...)
	finalStore = append(finalStore, encData...)
	userlib.DatastoreSet(uuid, finalStore)

	return &User{
		Username:       username,
		Rootkey:        rootKey,
		HashedPassword: userlib.Argon2Key([]byte(password), salt, 16),
		FileAccessMap:  userMeta.FileAccessMap,
	}, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	//step 1: Get User metadata after rederiving UUID
	//step 2: Extract stored values and rederive cryptographic keys
	//step 3: Verify integrity by recomputing HMAC over ciphertext and seeing that it matches
	//step 4: Decrypt the ciphertext and unmarshal the plaintext into the user struct
	//step 5: Return a new user struct

	if len(username) == 0 {
		return nil, errors.New("username cannot be empty")
	}

	// step 1: Derive UUID and get data
	hash := userlib.Hash([]byte(username))
	uid, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, err
	}

	data, ok := userlib.DatastoreGet(uid)
	if !ok {
		return nil, errors.New("user does not exist")
	}
	if len(data) < 80 {
		return nil, errors.New("corrupted user data: too short")
	}

	// step 2: Split data into salt, stored HMAC, and ciphertext
	salt := data[:16]
	storedHMAC := data[16:80]
	ciphertext := data[80:]

	rootKey := userlib.Argon2Key([]byte(password), salt, 16)
	encryptKey, _ := userlib.HashKDF(rootKey, []byte("encrypt"))
	hmacKey, _ := userlib.HashKDF(rootKey, []byte("hmac"))

	// verify the HMAC
	macCheck, err := userlib.HMACEval(hmacKey[:16], ciphertext)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(macCheck, storedHMAC) {
		return nil, errors.New("tampering detected")
	}

	// step 4: Decrypt and unmarshal
	plaintext := userlib.SymDec(encryptKey[:16], ciphertext)
	var userMeta Usermetadata
	err = json.Unmarshal(plaintext, &userMeta)
	if err != nil {
		return nil, err
	}

	// step 5: Return a new User struct
	return &User{
		Username:       username,
		Rootkey:        rootKey,
		HashedPassword: userlib.Argon2Key([]byte(password), salt, 16),
		FileAccessMap:  userMeta.FileAccessMap,
	}, nil
}

func (userdata *User) StoreFile(filename string, content []byte) error {
	filenameHash := userlib.Hash([]byte(filename))
	filenameKey := hex.EncodeToString(filenameHash[:16])

	contentEncKey := userlib.RandomBytes(16)
	contentIV := userlib.RandomBytes(16)
	encryptedContent := userlib.SymEnc(contentEncKey, contentIV, content)

	contentHMACKey := userlib.RandomBytes(16)
	contentHMAC, err := userlib.HMACEval(contentHMACKey, encryptedContent)
	if err != nil {
		return err
	}

	firstBlock := FileContent{
		FileData:      encryptedContent,
		HMAC:          contentHMAC,
		NextBlockUUID: nil,
	}
	firstBlockBytes, err := json.Marshal(firstBlock)
	if err != nil {
		return err
	}
	firstBlockUUID := uuid.New()
	userlib.DatastoreSet(firstBlockUUID, firstBlockBytes)

	fileMeta := FileMetadata{
		OwnerID:        userdata.Username,
		FileUUID:       firstBlockUUID,
		EncryptionKey:  contentEncKey,
		HMACKey:        contentHMACKey,
		SharedUsers:    make(map[string][]byte),
		VersionHistory: []uuid.UUID{firstBlockUUID},
		NumBlocks:      1,
		LastBlockLoc:   firstBlockUUID,
	}

	metaBytes, err := json.Marshal(fileMeta)
	if err != nil {
		return err
	}

	metaEncKey := userlib.RandomBytes(16)
	metaIV := userlib.RandomBytes(16)
	encMeta := userlib.SymEnc(metaEncKey, metaIV, metaBytes)

	metaHMACKey := userlib.RandomBytes(16)
	metaHMAC, err := userlib.HMACEval(metaHMACKey, encMeta)
	if err != nil {
		return err
	}

	finalMeta := append(metaHMAC, encMeta...)
	metaUUID := uuid.New()
	userlib.DatastoreSet(metaUUID, finalMeta)

	userdata.FileAccessMap[filenameKey] = AccessInfo{
		MetadataUUID: metaUUID,
		EncKey:       metaEncKey,
		HMACKey:      metaHMACKey,
	}

	userHash := userlib.Hash([]byte(userdata.Username))
	userUUID, err := uuid.FromBytes(userHash[:16])
	if err != nil {
		return err
	}

	record, ok := userlib.DatastoreGet(userUUID)
	if !ok || len(record) < 80 {
		return errors.New("user metadata missing or corrupted")
	}

	salt := record[:16]
	storedHMAC := record[16:80]
	encStoredMeta := record[80:]
	if len(storedHMAC) != 64 {
		return errors.New("user metadata HMAC size invalid")
	}

	encryptKey, _ := userlib.HashKDF(userdata.Rootkey, []byte("encrypt"))
	hmacKey, _ := userlib.HashKDF(userdata.Rootkey, []byte("hmac"))

	macCheck, err := userlib.HMACEval(hmacKey[:16], encStoredMeta)
	if err != nil || !userlib.HMACEqual(macCheck, storedHMAC) {
		return errors.New("user metadata integrity check failed")
	}

	metaPlain := userlib.SymDec(encryptKey[:16], encStoredMeta)

	var userMeta Usermetadata
	if err := json.Unmarshal(metaPlain, &userMeta); err != nil {
		return err
	}

	userMeta.FileAccessMap = userdata.FileAccessMap

	metaBytesUpdated, err := json.Marshal(userMeta)
	if err != nil {
		return err
	}

	newEncMeta := userlib.SymEnc(encryptKey[:16], userlib.RandomBytes(16), metaBytesUpdated)
	newHMAC, err := userlib.HMACEval(hmacKey[:16], newEncMeta)
	if err != nil {
		return err
	}

	finalRecord := append(salt, newHMAC...)
	finalRecord = append(finalRecord, newEncMeta...)
	userlib.DatastoreSet(userUUID, finalRecord)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	filenameHash := userlib.Hash([]byte(filename))
	filenameKey := hex.EncodeToString(filenameHash[:16])

	userHash := userlib.Hash([]byte(userdata.Username))
	userUUID, err := uuid.FromBytes(userHash[:16])
	if err != nil {
		return nil, err
	}

	record, ok := userlib.DatastoreGet(userUUID)
	if !ok || len(record) < 80 {
		return nil, errors.New("user metadata missing or corrupted")
	}
	storedHMAC := record[16:80]
	encStoredMeta := record[80:]
	if len(storedHMAC) != 64 {
		return nil, errors.New("user metadata HMAC size invalid")
	}

	encryptKey, _ := userlib.HashKDF(userdata.Rootkey, []byte("encrypt"))
	hmacKey, _ := userlib.HashKDF(userdata.Rootkey, []byte("hmac"))

	macCheck, err := userlib.HMACEval(hmacKey[:16], encStoredMeta)
	if err != nil || !userlib.HMACEqual(macCheck, storedHMAC) {
		return nil, errors.New("user metadata integrity check failed")
	}

	metaPlain := userlib.SymDec(encryptKey[:16], encStoredMeta)
	var userMeta Usermetadata
	if err := json.Unmarshal(metaPlain, &userMeta); err != nil {
		return nil, err
	}

	accessInfo, ok := userMeta.FileAccessMap[filenameKey]
	if !ok {
		return nil, errors.New("file not found in FileAccessMap")
	}

	metadataBytes, ok := userlib.DatastoreGet(accessInfo.MetadataUUID)
	if !ok || len(metadataBytes) < 64 {
		return nil, errors.New("file metadata missing or corrupted")
	}

	metaHMAC := metadataBytes[:64]
	encMeta := metadataBytes[64:]
	if len(metaHMAC) != 64 {
		return nil, errors.New("file metadata HMAC size invalid")
	}

	expectedMetaHMAC, err := userlib.HMACEval(accessInfo.HMACKey, encMeta)
	if err != nil || !userlib.HMACEqual(metaHMAC, expectedMetaHMAC) {
		return nil, errors.New("file metadata integrity check failed")
	}

	metaPlain = userlib.SymDec(accessInfo.EncKey, encMeta)
	var fileMeta FileMetadata
	err = json.Unmarshal(metaPlain, &fileMeta)
	if err != nil {
		return nil, err
	}

	var fileData []byte
	currUUID := fileMeta.FileUUID

	for {
		blockBytes, ok := userlib.DatastoreGet(currUUID)
		if !ok {
			return nil, errors.New("missing file block")
		}

		var block FileContent
		err := json.Unmarshal(blockBytes, &block)
		if err != nil {
			return nil, err
		}

		expectedHMAC, err := userlib.HMACEval(fileMeta.HMACKey, block.FileData)
		if err != nil || !userlib.HMACEqual(expectedHMAC, block.HMAC) {
			return nil, errors.New("file block integrity check failed")
		}

		plain := userlib.SymDec(fileMeta.EncryptionKey, block.FileData)
		fileData = append(fileData, plain...)

		if block.NextBlockUUID == nil {
			break
		}
		currUUID = *block.NextBlockUUID
	}

	return fileData, nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	filenameHash := userlib.Hash([]byte(filename))
	filenameKey := hex.EncodeToString(filenameHash[:16])

	userHash := userlib.Hash([]byte(userdata.Username))
	userUUID, err := uuid.FromBytes(userHash[:16])
	if err != nil {
		return err
	}

	record, ok := userlib.DatastoreGet(userUUID)
	if !ok || len(record) < 80 {
		return errors.New("user metadata missing or corrupted")
	}
	storedHMAC := record[16:80]
	encStoredMeta := record[80:]
	if len(storedHMAC) != 64 {
		return errors.New("user metadata HMAC size invalid")
	}

	encryptKey, _ := userlib.HashKDF(userdata.Rootkey, []byte("encrypt"))
	hmacKey, _ := userlib.HashKDF(userdata.Rootkey, []byte("hmac"))

	macCheck, err := userlib.HMACEval(hmacKey[:16], encStoredMeta)
	if err != nil || !userlib.HMACEqual(macCheck, storedHMAC) {
		return errors.New("user metadata integrity check failed")
	}

	metaPlain := userlib.SymDec(encryptKey[:16], encStoredMeta)
	var userMeta Usermetadata
	if err := json.Unmarshal(metaPlain, &userMeta); err != nil {
		return err
	}

	accessInfo, ok := userMeta.FileAccessMap[filenameKey]
	if !ok {
		return errors.New("file not found in user's file map")
	}

	metaBytes, ok := userlib.DatastoreGet(accessInfo.MetadataUUID)
	if !ok || len(metaBytes) < 64 {
		return errors.New("file metadata missing or corrupted")
	}

	metaHMAC := metaBytes[:64]
	encMeta := metaBytes[64:]
	if len(metaHMAC) != 64 {
		return errors.New("file metadata HMAC size invalid")
	}

	computedHMAC, err := userlib.HMACEval(accessInfo.HMACKey, encMeta)
	if err != nil || !userlib.HMACEqual(metaHMAC, computedHMAC) {
		return errors.New("file metadata integrity check failed")
	}

	metaPlain = userlib.SymDec(accessInfo.EncKey, encMeta)
	var fileMeta FileMetadata
	err = json.Unmarshal(metaPlain, &fileMeta)
	if err != nil {
		return err
	}

	newIV := userlib.RandomBytes(16)
	encContent := userlib.SymEnc(fileMeta.EncryptionKey, newIV, content)
	contentHMAC, err := userlib.HMACEval(fileMeta.HMACKey, encContent)
	if err != nil {
		return err
	}

	newBlock := FileContent{
		FileData:      encContent,
		HMAC:          contentHMAC,
		NextBlockUUID: nil,
	}

	newBlockBytes, err := json.Marshal(newBlock)
	if err != nil {
		return err
	}
	newBlockUUID := uuid.New()
	userlib.DatastoreSet(newBlockUUID, newBlockBytes)

	lastBlockBytes, ok := userlib.DatastoreGet(fileMeta.LastBlockLoc)
	if !ok {
		return errors.New("last block missing")
	}

	var lastBlock FileContent
	err = json.Unmarshal(lastBlockBytes, &lastBlock)
	if err != nil {
		return err
	}

	lastBlock.NextBlockUUID = &newBlockUUID
	updatedLastBlockBytes, err := json.Marshal(lastBlock)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileMeta.LastBlockLoc, updatedLastBlockBytes)

	fileMeta.LastBlockLoc = newBlockUUID
	fileMeta.NumBlocks++
	fileMeta.VersionHistory = append(fileMeta.VersionHistory, newBlockUUID)

	metaBytesUpdated, err := json.Marshal(fileMeta)
	if err != nil {
		return err
	}

	encMetaNew := userlib.SymEnc(accessInfo.EncKey, userlib.RandomBytes(16), metaBytesUpdated)
	hmacMetaNew, err := userlib.HMACEval(accessInfo.HMACKey, encMetaNew)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(accessInfo.MetadataUUID, append(hmacMetaNew, encMetaNew...))

	return nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// 1. Refresh user metadata
	userHash := userlib.Hash([]byte(userdata.Username))
	userUUID, err := uuid.FromBytes(userHash[:16])
	if err != nil {
		return uuid.Nil, err
	}
	record, ok := userlib.DatastoreGet(userUUID)
	if !ok || len(record) < 80 {
		return uuid.Nil, errors.New("user metadata missing or corrupted")
	}
	storedHMAC := record[16:80]
	encMeta := record[80:]

	encKey, _ := userlib.HashKDF(userdata.Rootkey, []byte("encrypt"))
	hmacKey, _ := userlib.HashKDF(userdata.Rootkey, []byte("hmac"))

	check, err := userlib.HMACEval(hmacKey[:16], encMeta)
	if err != nil || !userlib.HMACEqual(check, storedHMAC) {
		return uuid.Nil, errors.New("user metadata integrity check failed")
	}
	metaPlain := userlib.SymDec(encKey[:16], encMeta)

	var userMeta Usermetadata
	if err := json.Unmarshal(metaPlain, &userMeta); err != nil {
		return uuid.Nil, err
	}

	// 2. Look up AccessInfo for filename
	filenameHash := userlib.Hash([]byte(filename))
	filenameKey := hex.EncodeToString(filenameHash[:16])

	accessInfo, ok := userMeta.FileAccessMap[filenameKey]
	if !ok {
		return uuid.Nil, errors.New("file not found")
	}

	// 3. Get recipient's RSA encryption public key
	recipientEncKey, ok := userlib.KeystoreGet(recipientUsername + "_enc")
	if !ok {
		return uuid.Nil, errors.New("recipient public key not found")
	}

	// 4. Create the invitation payload
	type SharedAccessNode struct {
		OwnerUsername string
		MetadataUUID  uuid.UUID
		EncKey        []byte
		HMACKey       []byte
	}

	sharedAccess := SharedAccessNode{
		OwnerUsername: userdata.Username,
		MetadataUUID:  accessInfo.MetadataUUID,
		EncKey:        accessInfo.EncKey,
		HMACKey:       accessInfo.HMACKey,
	}

	sharedBytes, err := json.Marshal(sharedAccess)
	if err != nil {
		return uuid.Nil, err
	}

	symKey := userlib.RandomBytes(16)
	encShared := userlib.SymEnc(symKey, userlib.RandomBytes(16), sharedBytes)

	encSymKey, err := userlib.PKEEnc(recipientEncKey, symKey)
	if err != nil {
		return uuid.Nil, err
	}

	finalPayload := append(encSymKey, encShared...)

	// 5. Store the invitation
	sharedUUID := uuid.New()
	userlib.DatastoreSet(sharedUUID, finalPayload)

	// 6. Update FileMetadata to track that you shared
	metaRecord, ok := userlib.DatastoreGet(accessInfo.MetadataUUID)
	if !ok || len(metaRecord) < 64 {
		return uuid.Nil, errors.New("file metadata missing")
	}
	metaHMAC := metaRecord[:64]
	metaCipher := metaRecord[64:]

	expected, err := userlib.HMACEval(accessInfo.HMACKey, metaCipher)
	if err != nil || !userlib.HMACEqual(metaHMAC, expected) {
		return uuid.Nil, errors.New("metadata HMAC mismatch")
	}

	metaPlain = userlib.SymDec(accessInfo.EncKey, metaCipher)
	var fileMeta FileMetadata
	if err := json.Unmarshal(metaPlain, &fileMeta); err != nil {
		return uuid.Nil, err
	}

	fileMeta.SharedUsers[recipientUsername] = sharedUUID[:]

	metaBytes, err := json.Marshal(fileMeta)
	if err != nil {
		return uuid.Nil, err
	}

	encMetaUpdated := userlib.SymEnc(accessInfo.EncKey, userlib.RandomBytes(16), metaBytes)
	hmacUpdated, err := userlib.HMACEval(accessInfo.HMACKey, encMetaUpdated)
	if err != nil {
		return uuid.Nil, err
	}

	userlib.DatastoreSet(accessInfo.MetadataUUID, append(hmacUpdated, encMetaUpdated...))

	return sharedUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// 1. Load the latest persistent Usermetadata
	userHash := userlib.Hash([]byte(userdata.Username))
	userUUID, err := uuid.FromBytes(userHash[:16])
	if err != nil {
		return err
	}
	record, ok := userlib.DatastoreGet(userUUID)
	if !ok || len(record) < 80 {
		return errors.New("user metadata missing or corrupted")
	}
	salt := record[:16]
	storedHMAC := record[16:80]
	cipher := record[80:]

	encKey, _ := userlib.HashKDF(userdata.Rootkey, []byte("encrypt"))
	hmacKey, _ := userlib.HashKDF(userdata.Rootkey, []byte("hmac"))

	tag, err := userlib.HMACEval(hmacKey[:16], cipher)
	if err != nil || !userlib.HMACEqual(tag, storedHMAC) {
		return errors.New("user metadata integrity check failed")
	}

	plain := userlib.SymDec(encKey[:16], cipher)
	var userMeta Usermetadata
	if err := json.Unmarshal(plain, &userMeta); err != nil {
		return err
	}

	// Refresh the in-memory copy so the struct stays consistent
	userdata.FileAccessMap = userMeta.FileAccessMap

	// 2. Make sure filename isnt already taken
	filenameHash := userlib.Hash([]byte(filename))
	filenameKey := hex.EncodeToString(filenameHash[:16])
	if _, exists := userMeta.FileAccessMap[filenameKey]; exists {
		return errors.New("filename already exists in user's namespace")
	}

	// 3. Pull the invitation payload
	payload, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitation UUID not found")
	}
	if len(payload) < RSAKeySizeBytes {
		return errors.New("invitation payload malformed")
	}
	encSymKey := payload[:RSAKeySizeBytes]
	encShared := payload[RSAKeySizeBytes:]

	// we need the recipients RSA decryption key
	var priv struct {
		SKEnc  userlib.PKEDecKey
		SignSk userlib.DSSignKey
	}
	if err := json.Unmarshal(userMeta.PrivateKey, &priv); err != nil {
		return err
	}

	symKey, err := userlib.PKEDec(priv.SKEnc, encSymKey)
	if err != nil {
		return errors.New("cannot decrypt invitation")
	}
	sharedBytes := userlib.SymDec(symKey, encShared)

	type sharedNode struct {
		OwnerUsername string
		MetadataUUID  uuid.UUID
		EncKey        []byte
		HMACKey       []byte
	}
	var sn sharedNode
	if err := json.Unmarshal(sharedBytes, &sn); err != nil {
		return errors.New("invitation payload corrupted")
	}

	// 4. Validate the sender
	if sn.OwnerUsername != senderUsername {
		return errors.New("senderUsername mismatch")
	}
	if sn.OwnerUsername == userdata.Username {
		return errors.New("user cannot accept their own invitation")
	}

	// 5. Add entry to FileAccessMap
	userMeta.FileAccessMap[filenameKey] = AccessInfo{
		MetadataUUID: sn.MetadataUUID,
		EncKey:       sn.EncKey,
		HMACKey:      sn.HMACKey,
	}

	// mirror change in the live struct
	userdata.FileAccessMap = userMeta.FileAccessMap

	// 6. Re-encrypt & store updated Usermetadata
	updated, err := json.Marshal(userMeta)
	if err != nil {
		return err
	}
	newCipher := userlib.SymEnc(encKey[:16], userlib.RandomBytes(16), updated)
	newTag, err := userlib.HMACEval(hmacKey[:16], newCipher)
	if err != nil {
		return err
	}
	final := append(salt, newTag...)
	final = append(final, newCipher...)
	userlib.DatastoreSet(userUUID, final)

	// 7. Burn the invitation
	userlib.DatastoreDelete(invitationPtr)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// 1. Compute filename key
	filenameHash := userlib.Hash([]byte(filename))
	filenameKey := hex.EncodeToString(filenameHash[:16])

	// 2. Load & decrypt your my Usermetadata
	userHash := userlib.Hash([]byte(userdata.Username))
	userUUID, err := uuid.FromBytes(userHash[:16])
	if err != nil {
		return err
	}
	record, ok := userlib.DatastoreGet(userUUID)
	if !ok || len(record) < 80 {
		return errors.New("user metadata missing or corrupted")
	}
	salt := record[:16]
	storedHMAC := record[16:80]
	encUserMeta := record[80:]

	encKey, _ := userlib.HashKDF(userdata.Rootkey, []byte("encrypt"))
	hmacKey, _ := userlib.HashKDF(userdata.Rootkey, []byte("hmac"))
	check, err := userlib.HMACEval(hmacKey[:16], encUserMeta)
	if err != nil || !userlib.HMACEqual(check, storedHMAC) {
		return errors.New("user metadata integrity check failed")
	}
	plainUserMeta := userlib.SymDec(encKey[:16], encUserMeta)

	var userMeta Usermetadata
	if err := json.Unmarshal(plainUserMeta, &userMeta); err != nil {
		return err
	}

	// 3. Find the AccessInfo for this file
	accessInfo, ok := userMeta.FileAccessMap[filenameKey]
	if !ok {
		return errors.New("file not found in your namespace")
	}

	// 4. Load & decrypt the FileMetadata
	metaRecord, ok := userlib.DatastoreGet(accessInfo.MetadataUUID)
	if !ok || len(metaRecord) < 64 {
		return errors.New("file metadata missing or corrupted")
	}
	metaHMAC := metaRecord[:64]
	encFileMeta := metaRecord[64:]
	expected, err := userlib.HMACEval(accessInfo.HMACKey, encFileMeta)
	if err != nil || !userlib.HMACEqual(expected, metaHMAC) {
		return errors.New("file metadata integrity check failed")
	}
	plainFileMeta := userlib.SymDec(accessInfo.EncKey, encFileMeta)

	var fileMeta FileMetadata
	if err := json.Unmarshal(plainFileMeta, &fileMeta); err != nil {
		return err
	}

	// 5. Only the owner may revoke
	if fileMeta.OwnerID != userdata.Username {
		return errors.New("only the owner may revoke access")
	}

	// 6. Delete every invite UUID we previously stored
	for _, invitePtrBytes := range fileMeta.SharedUsers {
		if ptr, err := uuid.FromBytes(invitePtrBytes); err == nil {
			userlib.DatastoreDelete(ptr)
		}
	}
	// clear the SharedUsers map entirely
	fileMeta.SharedUsers = make(map[string][]byte)

	// 7. Delete the old FileMetadata record so anyone pointing at it now fails
	userlib.DatastoreDelete(accessInfo.MetadataUUID)

	// 8. Rotate to a fresh metadata UUID and new meta‐keys
	newMetaUUID := uuid.New()
	newMetaEncKey := userlib.RandomBytes(16)
	newMetaHMACKey := userlib.RandomBytes(16)

	// 9. Persist the updated fileMeta (no SharedUsers, same content‐keys)
	updatedMetaBytes, err := json.Marshal(fileMeta)
	if err != nil {
		return err
	}
	encMetaNew := userlib.SymEnc(newMetaEncKey, userlib.RandomBytes(userlib.AESBlockSizeBytes), updatedMetaBytes)
	hmacMetaNew, err := userlib.HMACEval(newMetaHMACKey, encMetaNew)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(newMetaUUID, append(hmacMetaNew, encMetaNew...))

	// 10. Update FileAccessMap to point at the new metadata
	userMeta.FileAccessMap[filenameKey] = AccessInfo{
		MetadataUUID: newMetaUUID,
		EncKey:       newMetaEncKey,
		HMACKey:      newMetaHMACKey,
	}

	// 11. Re‐encrypt and store updated Usermetadata
	updatedUserMeta, err := json.Marshal(userMeta)
	if err != nil {
		return err
	}
	encUserNew := userlib.SymEnc(encKey[:16], userlib.RandomBytes(userlib.AESBlockSizeBytes), updatedUserMeta)
	hmacUserNew, err := userlib.HMACEval(hmacKey[:16], encUserNew)
	if err != nil {
		return err
	}
	finalUserRecord := append(salt, hmacUserNew...)
	finalUserRecord = append(finalUserRecord, encUserNew...)
	userlib.DatastoreSet(userUUID, finalUserRecord)

	return nil
}
