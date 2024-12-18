//go:build cli
// +build cli
package main

import (
  "encoding/base64"
  "fmt"
  "os"
  "path/filepath"
  "strings"
  "github.com/golang/protobuf/proto"
  "github.com/urfave/cli/v2"
  v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
  "main/pkg/types"
  "main/pkg/fileutils"
  "main/pkg/encryption"
  "main/pkg/keyprocessing"
)

func ProcessFiles(files []string, passwords []string, source types.InputSource) (string, error) {
  var outputBuilder strings.Builder

  if len(files) == 0 {
      return "", fmt.Errorf("no files provided")
  }

  allSecret := make([]types.TempLocalState, 0, len(files))

  for i, f := range files {
      var password string
      if i < len(passwords) {
          password = passwords[i] // Use the corresponding password if available
      } else {
          password = "" // Default to an empty string if passwords are missing
      }

      if fileutils.IsBakFile(f) {
          result, err := fileutils.GetLocalStateFromBak(f, password, source)
          if err != nil {
              return "", fmt.Errorf("error reading file %s: %w", f, err)
          }
          outputBuilder.WriteString(fmt.Sprintf("Backup name: %v\n", f))
          outputBuilder.WriteString(fmt.Sprintf("This Share: %s\n", result[types.EdDSA].LocalPartyKey))
          outputBuilder.WriteString(fmt.Sprintf("All Shares: %v\n", result[types.EdDSA].KeygenCommitteeKeys))
          allSecret = append(allSecret, types.TempLocalState{
              FileName:   f,
              LocalState: result,
          })
      } else if strings.HasSuffix(f, "dat") {
          result, err := fileutils.GetLocalStateFromFile(f)
          if err != nil {
              return "", fmt.Errorf("error reading file %s: %w", f, err)
          }
          outputBuilder.WriteString(fmt.Sprintf("This Share: %s\n", result[types.EdDSA].LocalPartyKey))
          outputBuilder.WriteString(fmt.Sprintf("All Shares: %v\n", result[types.EdDSA].KeygenCommitteeKeys))
          allSecret = append(allSecret, types.TempLocalState{
              FileName:   f,
              LocalState: result,
          })
      }
  }

  threshold := len(files)
  keyTypes := []types.TssKeyType{types.ECDSA, types.EdDSA}
  for _, keyType := range keyTypes {
      if err := keyprocessing.GetKeys(threshold, allSecret, keyType, &outputBuilder); err != nil {
          return "", err
      }
  }

  return outputBuilder.String(), nil
}

func RecoverAction(cCtx *cli.Context) error {
  files := cCtx.StringSlice("files")
  //password := cCtx.StringSlice("password")
  // Create a slice of empty strings for passwords
  passwords := make([]string, len(files))
  source := types.CommandLine

  output, err := ProcessFiles(files, passwords, source)
  if err != nil {
      return err
  }

  // If running in CLI mode, print to console
  fmt.Println(output)
  return nil
}

func DecryptFileAction(ctx *cli.Context) error {
  for _, item := range ctx.Args().Slice() {
      filePathName, err := filepath.Abs(item)
      if err != nil {
          fmt.Printf("error getting absolute path for file %s: %s\n", item, err)
          continue
      }
      _, err = os.Stat(filePathName)
      if err != nil {
          fmt.Printf("error reading file %s: %s\n", item, err)
          continue
      }

      fileContent, err := fileutils.ReadFileContent(filePathName)
      if err != nil {
          fmt.Printf("error reading file %s: %s\n", item, err)
          continue
      }

      if fileutils.IsBakFile(filePathName) {
          rawContent, err := base64.StdEncoding.DecodeString(string(fileContent))
          if err != nil {
              fmt.Printf("error decoding file %s: %s\n", item, err)
              continue
          }
          var vaultContainer v1.VaultContainer
          if err := proto.Unmarshal(rawContent, &vaultContainer); err != nil {
              fmt.Printf("error unmarshalling file %s: %s\n", item, err)
              continue
          }
          // file is encrypted
          if vaultContainer.IsEncrypted {
              password := ""
              source := types.CommandLine
              decryptedVault, err := encryption.DecryptVault(&vaultContainer, filePathName, password, source)
              if err != nil {
                  fmt.Printf("error decrypting file %s: %s\n", item, err)
                  continue
              }
              fmt.Printf("%+v", decryptedVault)
          } else {
              fmt.Println("File is not encrypted")
          }
      }
  }
  return nil
}