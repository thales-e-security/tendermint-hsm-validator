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
	"encoding/json"

	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/tendermint/go-crypto"
	"github.com/tendermint/go-wire/data"
	"github.com/tendermint/tendermint/types"
)

// HsmPrivValidator is a Tendermint private validator that protects
// keys and critical blockchain logic within a Thales nShield HSM.
type HsmPrivValidator struct {
	EncryptedPrivKey []byte
	PublicKey        []byte
	Hsm              Hsm `json:"-"`
	keysLoaded       bool
}

// NewHsmPrivValidator constructs a new HsmPrivValidator, including
// generating a new key pair using the supplied Hsm interface. The
// key pair will not be loaded after generation.
func NewHsmPrivValidator(hsm Hsm) (HsmPrivValidator, error) {
	result := HsmPrivValidator{}
	pair, err := hsm.GenerateKey()
	if err != nil {
		return result, errors.WithMessage(err, "failed to generate key pair")
	}

	result.EncryptedPrivKey = pair.WrappedPrivateKey[:]
	result.PublicKey = pair.PublicKey[:]
	result.Hsm = hsm
	return result, nil
}

// LoadFromFile reads the privValidator from disk and loads the
// keys into the HSM.
func LoadFromFile(filePath string, hsm Hsm) (*HsmPrivValidator, error) {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var pv HsmPrivValidator
	err = json.Unmarshal(bytes, &pv)
	if err != nil {
		return nil, err
	}

	pv.Hsm = hsm
	err = pv.loadKeys()
	return &pv, errors.WithMessage(err, "failed to load keys")
}

// SaveToFile persists the private validator information to disk.
func (pv *HsmPrivValidator) SaveToFile(filePath string) error {

	bytes, err := json.Marshal(pv)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filePath, bytes, 0600)
}

// loadKeys loads the private key into the HSM
func (pv *HsmPrivValidator) loadKeys() error {
	err := pv.Hsm.LoadKeys(pv.EncryptedPrivKey)
	if err != nil {
		return err
	}

	pv.keysLoaded = true
	return nil
}

// GetAddress implements PrivValidator.GetAddress by simply
// calling GetPubKey().Address().
func (pv *HsmPrivValidator) GetAddress() data.Bytes {
	return pv.GetPubKey().Address()
}

// GetPubKey implements PrivValidator.GetPubKey and returns
// the Tendermint type that represents Ed25519 public keys.
func (pv *HsmPrivValidator) GetPubKey() crypto.PubKey {
	// We just borrow the Tendermint ed25519 type
	var pk [32]byte
	copy(pk[:], pv.PublicKey)
	return crypto.PubKey{crypto.PubKeyEd25519(pk)}
}

// SignVote implements PrivValidator.SignVote by sending the signing
// operation to the Thales HSM. This method will fail if there is a regression
// in height, round or step.
func (pv *HsmPrivValidator) SignVote(chainID string, vote *types.Vote) error {
	if !pv.keysLoaded {
		err := pv.loadKeys()
		if err != nil {
			return err
		}
	}

	bytes, err := pv.Hsm.SignVote(chainID, vote)
	if err != nil {
		return err
	}

	sig, err := makeSignatureFromBytes(bytes)
	if err != nil {
		return err
	}

	vote.Signature = sig
	return nil
}

// SignProposal implements PrivValidator.SignProposal by sending the signing
// operation to the Thales HSM. This method will fail if there is a regression
// in height, round or step.
func (pv *HsmPrivValidator) SignProposal(chainID string, proposal *types.Proposal) error {
	if !pv.keysLoaded {
		err := pv.loadKeys()
		if err != nil {
			return err
		}
	}

	bytes, err := pv.Hsm.SignProposal(chainID, proposal)
	if err != nil {
		return err
	}

	sig, err := makeSignatureFromBytes(bytes)
	if err != nil {
		return err
	}

	proposal.Signature = sig
	return nil
}

// SignHeartbeat implements PrivValidator.SignHeartbeat by sending the signing
// operation to the Thales HSM.
func (pv *HsmPrivValidator) SignHeartbeat(chainID string, heartbeat *types.Heartbeat) error {
	if !pv.keysLoaded {
		err := pv.loadKeys()
		if err != nil {
			return err
		}
	}

	bytes, err := pv.Hsm.SignHeartbeat(chainID, heartbeat)
	if err != nil {
		return err
	}

	sig, err := makeSignatureFromBytes(bytes)
	if err != nil {
		return err
	}

	heartbeat.Signature = sig
	return nil
}

// makeSignatureFromBytes validates the length of a signature, then wraps it in
// a Tendermint Signature type.
func makeSignatureFromBytes(sig []byte) (crypto.Signature, error) {
	const ed25519SigLength = 64
	if len(sig) != ed25519SigLength {
		return crypto.Signature{}, errors.Errorf(
			"expected %d byte signature, found %d bytes", ed25519SigLength, len(sig))
	}

	var sigBytes [64]byte
	copy(sigBytes[:], sig)

	return crypto.Signature{crypto.SignatureEd25519(sigBytes)}, nil
}
