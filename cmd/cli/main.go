//go:build cli
// +build cli
package main

import (
    "fmt"
    "os"
    "github.com/urfave/cli/v2"
)

func main() {
    fmt.Println("Running in command-line mode")
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
                    &cli.StringFlag{
                        Name:  "scheme",
                        Usage: "force scheme type (gg20, dkls, auto)",
                        Value: "auto",
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
    if err := app.Run(os.Args); err != nil {
        panic(err)
    }
}