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
	"fmt"

	tcrypto "github.com/tendermint/go-crypto"
	"github.com/tendermint/tendermint/types"
	"github.com/thales-e-security/tendermint-hsm-validator/module"
	"github.com/thales-e-security/tendermint-hsm-validator/validator"
)

// These values are hard-coded for convenience. In a real
// application they probably belong in a configuration file
const (
	host              = "127.0.0.1"
	port              = 49999
	privValidatorFile = "hsm-priv-validator.json"
	genesisFile       = "genesis.json"
)

func main() {

	hsm := module.ThalesHSM{
		Port: port,
		Host: host,
	}

	privValidator, err := validator.NewHsmPrivValidator(hsm)
	if err != nil {
		panic(err)
	}

	err = privValidator.SaveToFile(privValidatorFile)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Wrote private validator file to: %s\n", privValidatorFile)

	var pk [32]byte
	copy(pk[:], privValidator.PublicKey)

	genesisDoc := types.GenesisDoc{
		ChainID: "chain-hsm-test",
		Validators: []types.GenesisValidator{
			{
				PubKey: tcrypto.PubKey{tcrypto.PubKeyEd25519(pk)},
				Power:  10,
			},
		},
	}

	err = genesisDoc.SaveAs(genesisFile)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Wrote genesis file to: %s\n", genesisFile)
	fmt.Println("Done!")
}
