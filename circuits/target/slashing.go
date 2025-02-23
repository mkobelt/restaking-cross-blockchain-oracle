package target

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
	BlockHash     frontend.Variable `gnark:",public"`
	Request       frontend.Variable `gnark:",public"`
	Slasher       SlasherConstraints
	Validator     SlashedValidatorConstraints
}

type SlasherConstraints struct {
	Index             frontend.Variable `gnark:",public"`
	PublicKey         eddsa.PublicKey
	Balance           frontend.Variable
	MerkleProof       [restaking.Depth]frontend.Variable
	MerkleProofHelper frontend.Variable
}

type SlashedValidatorConstraints struct {
	Index             frontend.Variable `gnark:",public"`
	PublicKey         eddsa.PublicKey
	Balance           frontend.Variable
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

	//Verify that the account matches the leaf
	hFunc.Write(c.Validator.Index)
	hFunc.Write(c.Validator.PublicKey.A.X)
	hFunc.Write(c.Validator.PublicKey.A.Y)
	hFunc.Write(c.Validator.Balance)
	api.AssertIsEqual(hFunc.Sum(), c.Validator.MerkleProof[0])

	//Check validator included
	merkleProof := merkle.MerkleProof{
		RootHash: c.PreStateRoot,
		Path:     c.Validator.MerkleProof[:],
	}
	merkleProof.VerifyProof(api, &hFunc, c.Validator.MerkleProofHelper)

	//Create the message
	hFunc.Reset()
	hFunc.Write(c.Validator.Index)
	hFunc.Write(c.Request)
	hFunc.Write(c.Validator.BlockHash)
	msg := hFunc.Sum()

	hFunc.Reset()
	if err := eddsa.Verify(curve, c.Validator.Signature, msg, c.Validator.PublicKey, &hFunc); err != nil {
		return fmt.Errorf("verify eddsa: %w", err)
	}

	//Slash the validator
	hFunc.Reset()
	hFunc.Write(c.Validator.Index)
	hFunc.Write(c.Validator.PublicKey.A.X)
	hFunc.Write(c.Validator.PublicKey.A.Y)
	hFunc.Write(api.Sub(c.Validator.Balance, c.Validator.Balance))
	c.Validator.MerkleProof[0] = hFunc.Sum()

	//Compute new root
	root := restaking.ComputeRootFromPath(&merkleProof, api, &hFunc, c.Validator.MerkleProofHelper)

	// Verify that the public key from the Merkle proof matches the computed public key of the slasher
	hFunc.Reset()
	hFunc.Write(c.Slasher.Index)
	hFunc.Write(c.Slasher.PublicKey.A.X)
	hFunc.Write(c.Slasher.PublicKey.A.Y)
	hFunc.Write(c.Slasher.Balance)
	api.AssertIsEqual(hFunc.Sum(), c.Slasher.MerkleProof[0])

	// Check slasher included
	merkleProof = merkle.MerkleProof{
		RootHash: root,
		Path:     c.Validator.MerkleProof[:],
	}
	merkleProof.VerifyProof(api, &hFunc, c.Slasher.MerkleProofHelper)

	//Reward the slasher
	hFunc.Reset()
	hFunc.Write(c.Slasher.Index)
	hFunc.Write(c.Slasher.PublicKey.A.X)
	hFunc.Write(c.Slasher.PublicKey.A.Y)
	hFunc.Write(api.Add(c.Slasher.Balance, c.Validator.Balance))
	c.Slasher.MerkleProof[0] = hFunc.Sum()

	//Compute new root
	root = restaking.ComputeRootFromPath(&merkleProof, api, &hFunc, c.Slasher.MerkleProofHelper)

	api.AssertIsDifferent(c.BlockHash, c.Validator.BlockHash)
	api.AssertIsEqual(c.PostStateRoot, root)
	return nil
}
