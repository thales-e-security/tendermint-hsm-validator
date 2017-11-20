// Copyright 2017 Thales e-Security
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package main

import (
	"os"

	"github.com/tendermint/tmlibs/cli"
	"github.com/tendermint/tmlibs/log"

	tc "github.com/tendermint/tendermint/cmd/tendermint/commands"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/node"
	"github.com/tendermint/tendermint/proxy"
	"github.com/thales-e-security/tendermint-hsm-validator/module"
	"github.com/thales-e-security/tendermint-hsm-validator/validator"
)

var (
	config = cfg.DefaultConfig()
	logger = log.NewTMLogger(log.NewSyncWriter(os.Stdout)).With("module", "main")
)

// These values are hard-coded for convenience. In a real
// application they probably belong in a configuration file
const (
	host              = "127.0.0.1"
	port              = 49999
	privValidatorFile = "hsm-priv-validator.json"
)

func main() {
	rootCmd := tc.RootCmd
	rootCmd.AddCommand(tc.GenValidatorCmd)
	rootCmd.AddCommand(tc.InitFilesCmd)
	rootCmd.AddCommand(tc.ProbeUpnpCmd)
	rootCmd.AddCommand(tc.ReplayCmd)
	rootCmd.AddCommand(tc.ReplayConsoleCmd)
	rootCmd.AddCommand(tc.ResetAllCmd)
	rootCmd.AddCommand(tc.ResetPrivValidatorCmd)
	rootCmd.AddCommand(tc.ShowValidatorCmd)
	rootCmd.AddCommand(tc.TestnetFilesCmd)
	rootCmd.AddCommand(tc.VersionCmd)

	pathToValidatorFile := os.ExpandEnv("$HOME/.tendermint/") + privValidatorFile

	privValidator, err := validator.LoadFromFile(pathToValidatorFile, module.ThalesHSM{
		Host: host,
		Port: port,
	})

	if err != nil {
		panic(err)
	}

	rootCmd.AddCommand(tc.NewRunNodeCmd(func(config *cfg.Config, logger log.Logger) (*node.Node, error) {
		return node.NewNode(
			config,
			privValidator,
			proxy.DefaultClientCreator(config.ProxyApp, config.ABCI, config.DBDir()),
			node.DefaultGenesisDocProviderFunc(config),
			node.DefaultDBProvider,
			logger)
	}))

	cmd := cli.PrepareBaseCmd(rootCmd, "TM", os.ExpandEnv("$HOME/.tendermint"))
	cmd.Execute()
}
