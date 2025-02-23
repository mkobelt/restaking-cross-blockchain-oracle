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

const (
	AggregatorReward = 500000000000000
	ValidatorReward  = 20000000000
)

type AggregationCircuit struct {
	PreStateRoot  frontend.Variable `gnark:",public"`
	PostStateRoot frontend.Variable `gnark:",public"`
	BlockHash     frontend.Variable `gnark:",public"`
	Request       frontend.Variable `gnark:",public"`
	ValidatorBits frontend.Variable `gnark:",public"`
	Aggregator    AggregatorConstraints
	Validators    [restaking.NumAccounts]ValidatorConstraints
}

type AggregatorConstraints struct {
	Index             frontend.Variable    `gnark:",public"`
	PreSeed           twistededwards.Point `gnark:",public"`
	PostSeed          twistededwards.Point `gnark:",public"`
	SecretKey         frontend.Variable
	Balance           frontend.Variable
	MerkleProof       [restaking.Depth]frontend.Variable
	MerkleProofHelper frontend.Variable
}

type ValidatorConstraints struct {
	Index             frontend.Variable
	PublicKey         eddsa.PublicKey
	Balance           frontend.Variable
	MerkleProof       [restaking.Depth]frontend.Variable
	MerkleProofHelper frontend.Variable
	Signature         eddsa.Signature
	BlockHash         frontend.Variable
}

func (c *AggregationCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, edwards.BN254)
	if err != nil {
		return fmt.Errorf("edwards curve: %w", err)
	}

	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("mimc: %w", err)
	}

	//Check for duplicates
	for i := 0; i < restaking.NumAccounts; i++ {
		for j := 0; j < restaking.NumAccounts; j++ {
			if i == j {
				continue
			}
			api.AssertIsDifferent(c.Validators[i].Index, c.Validators[j].Index)
		}
	}

	//Compute next Seed
	postSeed := curve.ScalarMul(c.Aggregator.PreSeed, c.Aggregator.SecretKey)
	api.AssertIsEqual(c.Aggregator.PostSeed.X, postSeed.X)
	api.AssertIsEqual(c.Aggregator.PostSeed.Y, postSeed.Y)

	// Compute aggregator public key
	base := curve.Params().Base
	g := twistededwards.Point{X: base[0], Y: base[1]}
	pubKey := curve.ScalarMul(g, c.Aggregator.SecretKey)
	curve.AssertIsOnCurve(pubKey)

	// Verify that the public key from the Merkle proof matches the computed public key of the aggregator
	hFunc.Write(c.Aggregator.Index)
	hFunc.Write(pubKey.X)
	hFunc.Write(pubKey.Y)
	hFunc.Write(c.Aggregator.Balance)
	api.AssertIsEqual(hFunc.Sum(), c.Aggregator.MerkleProof[0])

	// Check aggregator included
	merkleProof := merkle.MerkleProof{
		RootHash: c.PreStateRoot,
		Path:     c.Aggregator.MerkleProof[:],
	}
	merkleProof.VerifyProof(api, &hFunc, c.Aggregator.MerkleProofHelper)

	//Reward the aggregator
	hFunc.Reset()
	hFunc.Write(c.Aggregator.Index)
	hFunc.Write(pubKey.X)
	hFunc.Write(pubKey.Y)
	hFunc.Write(api.Add(c.Aggregator.Balance, AggregatorReward))
	c.Aggregator.MerkleProof[0] = hFunc.Sum()

	//Compute new intermediate root
	intermediateRoot := restaking.ComputeRootFromPath(&merkleProof, api, &hFunc, c.Aggregator.MerkleProofHelper)

	validatorBits := frontend.Variable(0)

	for _, validator := range c.Validators {
		//Verify that the account matches the leaf
		hFunc.Reset()
		hFunc.Write(validator.Index)
		hFunc.Write(validator.PublicKey.A.X)
		hFunc.Write(validator.PublicKey.A.Y)
		hFunc.Write(validator.Balance)
		api.AssertIsEqual(hFunc.Sum(), validator.MerkleProof[0])

		//Check validator included
		merkleProof := merkle.MerkleProof{
			RootHash: intermediateRoot,
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

		api.AssertIsEqual(c.BlockHash, validator.BlockHash)

		//Reward the validator
		hFunc.Reset()
		hFunc.Write(validator.Index)
		hFunc.Write(validator.PublicKey.A.X)
		hFunc.Write(validator.PublicKey.A.Y)
		hFunc.Write(api.Add(validator.Balance, ValidatorReward))
		validator.MerkleProof[0] = hFunc.Sum()

		//Compute new intermediate root
		intermediateRoot = restaking.ComputeRootFromPath(&merkleProof, api, &hFunc, validator.MerkleProofHelper)

		validatorBits = api.Add(validatorBits, restaking.Pow(api, 2, validator.Index))
	}

	api.AssertIsEqual(c.ValidatorBits, validatorBits)

	api.AssertIsEqual(c.PostStateRoot, intermediateRoot)

	return nil
}
