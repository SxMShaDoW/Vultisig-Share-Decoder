//go:build cli
// +build cli

package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/vultisig/vsd/internal/format"
	"github.com/vultisig/vsd/internal/recovery"
	"github.com/vultisig/vsd/internal/vault"
)

func main() {
	app := cli.App{
		Name:  "vsd",
		Usage: "Recover private keys from Vultisig TSS vault shares",
		Commands: []*cli.Command{
			{
				Name: "recover",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:     "files",
						Usage:    "path to key share files",
						Required: true,
					},
					&cli.StringSliceFlag{
						Name:  "password",
						Usage: "password for encrypted vault files",
					},
					&cli.StringFlag{
						Name:  "scheme",
						Usage: "force scheme type (gg20, dkls, auto)",
						Value: "auto",
					},
					&cli.StringFlag{
						Name:  "format",
						Usage: "output format (text, json)",
						Value: "text",
					},
				},
				Action: recoverAction,
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func recoverAction(c *cli.Context) error {
	files := c.StringSlice("files")
	scheme := c.String("scheme")
	outputFormat := c.String("format")
	passwordArgs := c.StringSlice("password")

	passwords := make([]string, len(files))
	for i := 0; i < len(passwordArgs) && i < len(files); i++ {
		passwords[i] = passwordArgs[i]
	}

	inputs := make([]vault.FileInput, 0, len(files))
	for _, f := range files {
		content, err := vault.ReadFileContent(f)
		if err != nil {
			return fmt.Errorf("error reading file %s: %w", f, err)
		}
		inputs = append(inputs, vault.FileInput{
			Name:    f,
			Content: content,
		})
	}

	result, err := recovery.Recover(inputs, passwords, scheme)
	if err != nil {
		if outputFormat == "json" {
			errResult := &recovery.RecoveryResult{
				Success: false,
				Error:   err.Error(),
			}
			jsonOut, _ := format.JSON(errResult)
			fmt.Println(jsonOut)
			return nil
		}
		return fmt.Errorf("recovery failed: %w", err)
	}

	if outputFormat == "json" {
		jsonOut, err := format.JSON(result)
		if err != nil {
			return err
		}
		fmt.Println(jsonOut)
	} else {
		fmt.Print(format.Text(result))
	}
	return nil
}
