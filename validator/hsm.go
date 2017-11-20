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

package validator

import (
	"github.com/tendermint/tendermint/types"
)

// Ed25519KeyPair is an encrypted private ed25519 elliptic curve
// key with a corresponding public key.
type Ed25519KeyPair struct {
	PublicKey         [32]byte
	WrappedPrivateKey [64]byte
}

// Hsm defines the interface to the HSM.
type Hsm interface {
	// LoadKeys loads the encrypted private key into the HSM.
	LoadKeys(wrappedPrivKey []byte) error

	// GenerateKey creates a new ed25519 key pair in the HSM and returns
	// the encrypted private key and the public key.
	GenerateKey() (Ed25519KeyPair, error)

	// SignVote creates a canonical representation of the vote and signs
	// it in the HSM. The signing operation must fail if there is a
	// regression in height, round or step.
	SignVote(chainId string, vote *types.Vote) ([]byte, error)

	// SignProposal creates a canonical representation of the proposal and signs
	// it in the HSM. The signing operation must fail if there is a
	// regression in height, round or step.
	SignProposal(chainId string, proposal *types.Proposal) ([]byte, error)

	// SignHeartbeat creates a canonical representation of the heartbeat and signs
	// it in the HSM.
	SignHeartbeat(chainId string, hb *types.Heartbeat) ([]byte, error)
}
