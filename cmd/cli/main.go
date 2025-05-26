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
        },
    }
    if err := app.Run(os.Args); err != nil {
        panic(err)
    }
}