package main

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

func DecryptVault(password string, vault []byte) ([]byte, error) {
  // Hash the password to create a key
  hash := sha256.Sum256([]byte(password))
  key := hash[:]

  // Create a new AES cipher using the key
  block, err := aes.NewCipher(key)
  if err != nil {
    return nil, err
  }

  // Use GCM (Galois/Counter Mode)
  gcm, err := cipher.NewGCM(block)
  if err != nil {
    return nil, err
  }

  // Get the nonce size
  nonceSize := gcm.NonceSize()
  if len(vault) < nonceSize {
    return nil, fmt.Errorf("ciphertext too short")
  }

  // Extract the nonce from the vault
  nonce, ciphertext := vault[:nonceSize], vault[nonceSize:]

  // Decrypt the vault
  plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
  if err != nil {
    return nil, err
  }

  return plaintext, nil
}

func decryptVault(vaultContainer *v1.VaultContainer, inputFileName string, password string, source InputSource) (*v1.Vault, error) {
  vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
  if err != nil {
    return nil, fmt.Errorf("failed to decode vault: %w", err)
  }

  //If no password is provided, prompt for one
  if vaultContainer.IsEncrypted && source == CommandLine {
    if password == "" {
      fmt.Printf("Enter password to decrypt the vault (%s): ", inputFileName)
      bytePassword, err := term.ReadPassword(int(syscall.Stdin))
      if err != nil {
        return nil, fmt.Errorf("failed to read password: %w", err)
      }
      password = string(bytePassword)
    }
  }

  // Attempt to decrypt the vault using the provided or entered password
  decryptedVaultData, err := DecryptVault(password, vaultData)
  if err != nil {
    return nil, fmt.Errorf("error decrypting file %s: %w", inputFileName, err)
  }

  var vault v1.Vault
  if err := proto.Unmarshal(decryptedVaultData, &vault); err != nil {
    return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
  }

  return &vault, nil
}