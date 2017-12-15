package pgp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"os"
)

func getPublicKeyPacket(publicKey []byte) (*packet.PublicKey, error) {
	publicKeyReader := bytes.NewReader(publicKey)
	block, err := armor.Decode(publicKeyReader)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.PublicKeyType {
		return nil, errors.New("Invalid public key data")
	}

	packetReader := packet.NewReader(block.Body)
	pkt, err := packetReader.Next()
	if err != nil {
		return nil, err
	}

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, err
	}
	return key, nil
}

func getPrivateKeyPacket(privateKey []byte) (*packet.PrivateKey, error) {
	privateKeyReader := bytes.NewReader(privateKey)
	block, err := armor.Decode(privateKeyReader)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.PrivateKeyType {
		return nil, errors.New("Invalid private key data")
	}

	packetReader := packet.NewReader(block.Body)
	pkt, err := packetReader.Next()
	if err != nil {
		return nil, err
	}
	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		return nil, errors.New("Unable to cast to Private Key")
	}
	return key, nil
}

func OpenKeyring(keyringPath string) (openpgp.EntityList, error) {
	keyringFileBuffer, err := os.Open(keyringPath)
	if err != nil {
		return nil, err
	}
	defer keyringFileBuffer.Close()
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return nil, err
	}
	return entityList, nil
}

func GetKeyByEmail(keyring openpgp.EntityList, email string) *openpgp.Entity {
	for _, entity := range keyring {
		for _, ident := range entity.Identities {
			if ident.UserId.Email == email {
				return entity
			}
		}
	}

	return nil
}

func GetFingerprint(entity *openpgp.Entity) string {
	fingerprint := entity.PrimaryKey.Fingerprint[:]
	dst := make([]byte, hex.EncodedLen(len(fingerprint)))
	hex.Encode(dst, fingerprint)
	return string(dst)
}
