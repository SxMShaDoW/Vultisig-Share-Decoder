package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"syscall"

	"github.com/golang/protobuf/proto"
	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"golang.org/x/term"
)

func DecryptWithPassword(encryptedData []byte, password string) ([]byte, error) {
	vaultData, err := base64.StdEncoding.DecodeString(string(encryptedData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode vault data: %w", err)
	}

	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(vaultData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := vaultData[:nonceSize], vaultData[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func decryptVaultHelper(password string, vault []byte) ([]byte, error) {
	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(vault) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := vault[:nonceSize], vault[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func decryptVault(vaultContainer *v1.VaultContainer, fileName string, password string, source InputSource) (*v1.Vault, error) {
	vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vault: %w", err)
	}

	if vaultContainer.IsEncrypted && source == CommandLine {
		if password == "" {
			fmt.Printf("Enter password to decrypt the vault (%s): ", fileName)
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return nil, fmt.Errorf("failed to read password: %w", err)
			}
			password = string(bytePassword)
			fmt.Println()
		}
	}

	decryptedVaultData, err := decryptVaultHelper(password, vaultData)
	if err != nil {
		return nil, fmt.Errorf("error decrypting file %s: %w", fileName, err)
	}

	var v v1.Vault
	err = proto.Unmarshal(decryptedVaultData, &v)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
	}

	return &v, nil
}
