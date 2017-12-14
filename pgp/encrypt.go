package pgp

import (
	"bytes"
	_ "crypto/sha256"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	_ "golang.org/x/crypto/ripemd160"
	"io"
)

func Encrypt(entity *openpgp.Entity, message []byte) ([]byte, error) {
	// Create buffer to write output to
	buf := new(bytes.Buffer)

	// Create encoder
	encoderWriter, err := armor.Encode(buf, "PGP MESSAGE", nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error creating OpenPGP armor: %v", err)
	}

	// Create compressor with encoder
	compressorWriter, err := packet.SerializeCompressed(encoderWriter, packet.CompressionZIP, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error creating ZIP compressor: %v", err)
	}

	// Create encryptor with compressor
	encryptorWriter, err := openpgp.Encrypt(compressorWriter, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error creating entity for encryption: %v", err)
	}

	// Write message to encryptor
	messageReader := bytes.NewReader(message)
	_, err = io.Copy(encryptorWriter, messageReader)
	if err != nil {
		return []byte{}, fmt.Errorf("Error writing data to encryptor: %v", err)
	}

	encryptorWriter.Close()
	compressorWriter.Close()
	// No need to close the encoder here

	// Return buffer output - an encoded, compressed and encrypted message
	return buf.Bytes(), nil
}
