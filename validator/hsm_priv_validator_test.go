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

package validator_test // in this package to avoid mocking circular dependencies

import (
	"fmt"
	"os"
	"testing"
	"time"

	"crypto/rand"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/go-crypto"
	"github.com/tendermint/tendermint/types"
	"github.com/thales-e-security/tendermint-hsm-validator/mocks"
	"github.com/thales-e-security/tendermint-hsm-validator/validator"
)

func TestSaveRestoreAndLoad(t *testing.T) {
	tempfilename := fmt.Sprintf("%s/TestSaveAndRestore-%d", os.TempDir(), time.Now().Unix())

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHSM := mocks.NewMockHsm(mockCtrl)

	pv := validator.HsmPrivValidator{
		Hsm:              mockHSM,
		PublicKey:        []byte("public key"),
		EncryptedPrivKey: []byte("private key"),
	}

	pv.SaveToFile(tempfilename)

	_, err := os.Stat(tempfilename)
	require.NoError(t, err)
	defer os.Remove(tempfilename)

	mockHSM.EXPECT().LoadKeys(pv.EncryptedPrivKey).Return(nil).Times(1)

	pv2, err := validator.LoadFromFile(tempfilename, mockHSM)
	require.NoError(t, err)
	require.Equal(t, pv.PublicKey, pv2.PublicKey)
	require.Equal(t, pv.EncryptedPrivKey, pv2.EncryptedPrivKey)
}

func TestGetPubKeyAndAddress(t *testing.T) {
	var randomKey [32]byte
	rand.Read(randomKey[:])

	pv := &validator.HsmPrivValidator{
		PublicKey: randomKey[:],
	}

	edpubKey := pv.GetPubKey().PubKeyInner.(crypto.PubKeyEd25519)
	require.Equal(t, randomKey, [32]byte(edpubKey))

	origPubKey := crypto.PubKeyEd25519(randomKey)
	require.Equal(t, origPubKey.Address(), []byte(pv.GetAddress()))
}

func TestNewHsmPrivValidator(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	pair := validator.Ed25519KeyPair{}

	rand.Read(pair.PublicKey[:])
	rand.Read(pair.WrappedPrivateKey[:])

	mockHSM := mocks.NewMockHsm(mockCtrl)
	mockHSM.EXPECT().GenerateKey().Return(pair, nil).Times(1)

	pv, err := validator.NewHsmPrivValidator(mockHSM)
	require.NoError(t, err)

	require.Equal(t, pair.PublicKey[:], pv.PublicKey)
	require.Equal(t, pair.WrappedPrivateKey[:], pv.EncryptedPrivKey)
}

func TestSignVote(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockHSM := mocks.NewMockHsm(mockCtrl)

	const chainID = "chainID"

	vote := types.Vote{}

	var sig [64]byte
	rand.Read(sig[:])

	pk := []byte("private key")

	mockHSM.EXPECT().SignVote(chainID, &vote).Return(sig[:], nil).Times(1)
	mockHSM.EXPECT().LoadKeys(pk).Return(nil).Times(1)

	pv := validator.HsmPrivValidator{
		EncryptedPrivKey: pk,
		Hsm:              mockHSM,
	}

	err := pv.SignVote(chainID, &vote)
	require.NoError(t, err)

	result := [64]byte(vote.Signature.SignatureInner.(crypto.SignatureEd25519))
	require.Equal(t, sig, result)
}

func TestSignProposal(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockHSM := mocks.NewMockHsm(mockCtrl)

	const chainID = "chainID"

	proposal := types.Proposal{}

	var sig [64]byte
	rand.Read(sig[:])

	pk := []byte("private key")

	mockHSM.EXPECT().SignProposal(chainID, &proposal).Return(sig[:], nil).Times(1)
	mockHSM.EXPECT().LoadKeys(pk).Return(nil).Times(1)

	pv := validator.HsmPrivValidator{
		EncryptedPrivKey: pk,
		Hsm:              mockHSM,
	}

	err := pv.SignProposal(chainID, &proposal)
	require.NoError(t, err)

	result := [64]byte(proposal.Signature.SignatureInner.(crypto.SignatureEd25519))
	require.Equal(t, sig, result)
}

func TestSignHeartbeat(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockHSM := mocks.NewMockHsm(mockCtrl)

	const chainID = "chainID"

	heartbeat := types.Heartbeat{}

	var sig [64]byte
	rand.Read(sig[:])

	pk := []byte("private key")

	mockHSM.EXPECT().SignHeartbeat(chainID, &heartbeat).Return(sig[:], nil).Times(1)
	mockHSM.EXPECT().LoadKeys(pk).Return(nil).Times(1)

	pv := validator.HsmPrivValidator{
		EncryptedPrivKey: pk,
		Hsm:              mockHSM,
	}

	err := pv.SignHeartbeat(chainID, &heartbeat)
	require.NoError(t, err)

	result := [64]byte(heartbeat.Signature.SignatureInner.(crypto.SignatureEd25519))
	require.Equal(t, sig, result)
}
