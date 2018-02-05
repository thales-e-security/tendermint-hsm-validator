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

package module

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/tendermint/tendermint/types"
	"github.com/thales-e-security/tendermint-hsm-validator/validator"
)

const (
	seeJobKeyLoad       = iota
	seeJobKeyGen        = iota
	seeJobSignVote      = iota
	seeJobSignProposal  = iota
	seeJobSignHeartbeat = iota
)

// ThalesHSM implements validator.Hsm and is the interface
// to the CodeSafe machine running inside the nShield HSM. The
// CodeSafe machine will respond to instructions sent to its
// network interface (hence Port, Host).
type ThalesHSM struct {
	Port int
	Host string
}

// LoadKeys implements Hsm.LoadKeys by sending the encrypted key to the
// HSM to be loaded.
func (h ThalesHSM) LoadKeys(wrappedPrivKey []byte) error {
	buffer, err := MarshallAll(wrappedPrivKey)
	if err != nil {
		return err
	}

	_, err = SendJobToModule(seeJobKeyLoad, buffer, h.Host, h.Port)
	return err
}

// GenerateKey implements Hsm.GenerateKey by creating a new ed25519 key pair in
// the HSM and returning an encrypted copy of the private key and
// the public key.
func (h ThalesHSM) GenerateKey() (validator.Ed25519KeyPair, error) {
	response := validator.Ed25519KeyPair{}
	buffer := new(bytes.Buffer)

	result, err := SendJobToModule(seeJobKeyGen, buffer, h.Host, h.Port)
	if err != nil {
		return response, err
	}

	buffer = bytes.NewBuffer(result)

	var pubKey, privKey []byte

	err = UnmarshallAll(buffer, &pubKey, &privKey)
	if err != nil {
		return response, err
	}

	if len(pubKey) != len(response.PublicKey) {
		return response, errors.New(
			fmt.Sprintf("Bad public key size: got %d, expected %d", len(pubKey), len(response.PublicKey)))
	}

	copy(response.PublicKey[:], pubKey)

	if len(privKey) != len(response.WrappedPrivateKey) {
		return response, errors.New(
			fmt.Sprintf("Bad private key size: got %d, expected %d", len(privKey),
				len(response.WrappedPrivateKey)))
	}

	copy(response.WrappedPrivateKey[:], privKey)
	return response, nil
}

// SignVote implements Hsm.SignVote by signing the canonical representation of the vote,
// within the HSM. This operation will fail if there is a regression in round, step or height.
func (h ThalesHSM) SignVote(chainId string, vote *types.Vote) ([]byte, error) {
	buffer, err := MarshallAll(chainId, []byte(vote.BlockID.Hash), []byte(vote.BlockID.PartsHeader.Hash),
		vote.BlockID.PartsHeader.Total, vote.Height, vote.Round, types.CanonicalTime(vote.Timestamp), vote.Type)
	if err != nil {
		return nil, err
	}

	result, err := SendJobToModule(seeJobSignVote, buffer, h.Host, h.Port)
	if err != nil {
		return nil, err
	}

	buffer = bytes.NewBuffer(result)
	return UnmarshallBytes(buffer)
}

// SignProposal implements Hsm.SignProposal by signing the canonical representation of the proposal,
// within the HSM. This operation will fail if there is a regression in round, step or height.
func (h ThalesHSM) SignProposal(chainId string, proposal *types.Proposal) ([]byte, error) {
	// If pol_round == -1, we won't have these pieces of data:
	var polBlockIDHash []byte
	var partsHash []byte
	var partsTotal int

	if proposal.POLRound == -1 {
		polBlockIDHash = []byte{}
		partsHash = []byte{}
	} else {
		polBlockIDHash = proposal.POLBlockID.Hash
		partsHash = proposal.POLBlockID.PartsHeader.Hash
		partsTotal = proposal.POLBlockID.PartsHeader.Total
	}

	buffer, err := MarshallAll(chainId, []byte(proposal.BlockPartsHeader.Hash), proposal.BlockPartsHeader.Total,
		proposal.Height, polBlockIDHash, partsHash, partsTotal, proposal.POLRound, proposal.Round,
		types.CanonicalTime(proposal.Timestamp))
	if err != nil {
		return nil, err
	}

	result, err := SendJobToModule(seeJobSignProposal, buffer, h.Host, h.Port)
	if err != nil {
		return nil, err
	}

	buffer = bytes.NewBuffer(result)
	return UnmarshallBytes(buffer)
}

// SignHeartbeat implements Hsm.SignHeartbeat by signing the canonical representation of the heartbeat,
// within the HSM.
func (h ThalesHSM) SignHeartbeat(chainId string, hb *types.Heartbeat) ([]byte, error) {
	buffer, err := MarshallAll(chainId, hb.Height, hb.Round, hb.Sequence, []byte(hb.ValidatorAddress),
		hb.ValidatorIndex)
	if err != nil {
		return nil, err
	}

	result, err := SendJobToModule(seeJobSignHeartbeat, buffer, h.Host, h.Port)
	if err != nil {
		return nil, err
	}

	buffer = bytes.NewBuffer(result)
	return UnmarshallBytes(buffer)
}
