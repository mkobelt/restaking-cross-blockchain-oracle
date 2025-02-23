package restaking

import (
	"fmt"

	edwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/mkobelt/restaking"
)

type SlashingCircuit struct {
	PreStateRoot  frontend.Variable `gnark:",public"`
	PostStateRoot frontend.Variable `gnark:",public"`
	Request       frontend.Variable `gnark:",public"`
	BlockHash     frontend.Variable `gnark:",public"`
	Validators    [restaking.NumAccounts]ValidatorConstraints
	Slashed       SlashedValidatorConstraints
}

type ValidatorConstraints struct {
	Index             frontend.Variable
	PublicKey         eddsa.PublicKey
	Stake             frontend.Variable
	MerkleProof       [restaking.Depth]frontend.Variable
	MerkleProofHelper frontend.Variable
	Signature         eddsa.Signature
}

type SlashedValidatorConstraints struct {
	Index             frontend.Variable `gnark:",public"`
	PublicKey         eddsa.PublicKey
	Stake             frontend.Variable
	MerkleProof       [restaking.Depth]frontend.Variable
	MerkleProofHelper frontend.Variable
	Signature         eddsa.Signature
	BlockHash         frontend.Variable
}

func (c *SlashingCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, edwards.BN254)
	if err != nil {
		return fmt.Errorf("edwards curve: %w", err)
	}

	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("mimc: %w", err)
	}

	//Check for duplicates
	for i := range restaking.NumAccounts {
		for j := range restaking.NumAccounts {
			if i == j {
				continue
			}
			api.AssertIsDifferent(c.Validators[i].Index, c.Validators[j].Index)
		}
	}

	for _, validator := range c.Validators {
		//Verify that the account matches the leaf
		hFunc.Reset()
		hFunc.Write(validator.Index)
		hFunc.Write(validator.PublicKey.A.X)
		hFunc.Write(validator.PublicKey.A.Y)
		hFunc.Write(validator.Stake)
		api.AssertIsEqual(hFunc.Sum(), validator.MerkleProof[0])

		//Check validator included
		merkleProof := merkle.MerkleProof{
			RootHash: c.PreStateRoot,
			Path:     validator.MerkleProof[:],
		}
		merkleProof.VerifyProof(api, &hFunc, validator.MerkleProofHelper)

		//Create the message
		hFunc.Reset()
		hFunc.Write(validator.Index)
		hFunc.Write(c.Request)
		hFunc.Write(c.BlockHash)
		msg := hFunc.Sum()

		hFunc.Reset()
		if err := eddsa.Verify(curve, validator.Signature, msg, validator.PublicKey, &hFunc); err != nil {
			return fmt.Errorf("verify eddsa: %w", err)
		}
	}

	//Verify that the account matches the leaf
	hFunc.Reset()
	hFunc.Write(c.Slashed.Index)
	hFunc.Write(c.Slashed.PublicKey.A.X)
	hFunc.Write(c.Slashed.PublicKey.A.Y)
	hFunc.Write(c.Slashed.Stake)
	api.AssertIsEqual(hFunc.Sum(), c.Slashed.MerkleProof[0])

	//Check validator included
	merkleProof := merkle.MerkleProof{
		RootHash: c.PreStateRoot,
		Path:     c.Slashed.MerkleProof[:],
	}
	merkleProof.VerifyProof(api, &hFunc, c.Slashed.MerkleProofHelper)

	//Create the message
	hFunc.Reset()
	hFunc.Write(c.Slashed.Index)
	hFunc.Write(c.Request)
	hFunc.Write(c.Slashed.BlockHash)
	msg := hFunc.Sum()

	hFunc.Reset()
	if err := eddsa.Verify(curve, c.Slashed.Signature, msg, c.Slashed.PublicKey, &hFunc); err != nil {
		return fmt.Errorf("verify eddsa: %w", err)
	}

	//Slash the validator
	hFunc.Reset()
	hFunc.Write(c.Slashed.Index)
	hFunc.Write(c.Slashed.PublicKey.A.X)
	hFunc.Write(c.Slashed.PublicKey.A.Y)
	hFunc.Write(0)
	c.Slashed.MerkleProof[0] = hFunc.Sum()

	api.AssertIsEqual(c.PostStateRoot, restaking.ComputeRootFromPath(&merkleProof, api, &hFunc, c.Slashed.MerkleProofHelper))

	return nil
}
