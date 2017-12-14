package pgp

import (
	"bytes"
	_ "crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	_ "golang.org/x/crypto/ripemd160"
	"io/ioutil"
)

func Decrypt(entity *openpgp.Entity, encrypted []byte) ([]byte, error) {
	// Decode message
	block, err := armor.Decode(bytes.NewReader(encrypted))
	if err != nil {
		return []byte{}, fmt.Errorf("Error decoding: %v", err)
	}
	if block.Type != "PGP MESSAGE" {
		return []byte{}, errors.New("Invalid message type")
	}

	// Uncompress message
	compressed, err := packet.Read(block.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to read Compressed: %v", err)
	}
	c, ok := compressed.(*packet.Compressed)
	if !ok {
		return []byte{}, fmt.Errorf("didn't find Compressed packet")
	}

	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(c.Body, entityList, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading message: %v", err)
	}
	read, err := ioutil.ReadAll(messageReader.UnverifiedBody)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading unverified body: %v", err)
	}
	out := read

	// Return output - an unencoded, unencrypted, and uncompressed message
	return out, nil
}
