//go:build cli
// +build cli

package main

import (
    "fmt"
    "os"
    "github.com/urfave/cli/v2"
)

func main() {
    app := cli.App{
        Name:  "key-recover",
        Usage: "Recover a key from a set of TSS key shares",
        Commands: []*cli.Command{
            {
                Name:   "decrypt",
                Action: DecryptFileAction,
                Usage:  "decrypt files",
            },
            {
                Name: "recover",
                Flags: []cli.Flag{
                    &cli.StringSliceFlag{
                        Name:       "files",
                        Usage:      "path to key share files",
                        Required:   true,
                        HasBeenSet: false,
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
                Action: RecoverAction,
            },
            {
                Name: "test-address",
                Flags: []cli.Flag{
                    &cli.StringFlag{
                        Name:     "private-key",
                        Usage:    "private key in hex format",
                        Required: true,
                    },
                    &cli.StringFlag{
                        Name:     "chaincode",
                        Usage:    "chaincode in hex format",
                        Required: true,
                    },
                },
                Action: TestAddressAction,
                Usage:  "test address generation from private key",
            },
        },
    }
    err := app.Run(os.Args)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
}