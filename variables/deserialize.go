package variables

import (
	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"math/big"
)

func HashesToVars(hs []types.HashElements) []frontend.Variable {
	ret := make([]frontend.Variable, len(hs))
	for i, h := range hs {
		ret[i] = HashToVar(h)
	}
	return ret
}

func HashToVar(h types.HashElements) frontend.Variable {
	if len(h.Elements) < 1 {
		panic("invalid amount of hash elements")
	}
	mod := new(big.Int).SetUint64(0xFFFFFFFF00000001)
	res := new(big.Int).SetUint64(h.Elements[0])
	for i, el := range h.Elements[1:] {
		elBig := new(big.Int).SetUint64(el)
		shift := new(big.Int).Exp(mod, big.NewInt(int64(i+1)), nil)
		res.Add(res, new(big.Int).Mul(elBig, shift))
	}
	return res
}

func DeserializeMerkleCap(merkleCapRaw []types.HashElements) FriMerkleCap {
	n := len(merkleCapRaw)
	merkleCap := make([]poseidon.BN254HashOut, n)
	for i := 0; i < n; i++ {
		merkleCap[i] = HashToVar(merkleCapRaw[i])
	}
	return merkleCap
}

func DeserializeOpeningSet(openingSetRaw struct {
	Constants       [][]uint64
	PlonkSigmas     [][]uint64
	Wires           [][]uint64
	PlonkZs         [][]uint64
	PlonkZsNext     [][]uint64
	PartialProducts [][]uint64
	QuotientPolys   [][]uint64
}) OpeningSet {
	return OpeningSet{
		Constants:       gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.Constants),
		PlonkSigmas:     gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkSigmas),
		Wires:           gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.Wires),
		PlonkZs:         gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkZs),
		PlonkZsNext:     gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PlonkZsNext),
		PartialProducts: gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.PartialProducts),
		QuotientPolys:   gl.Uint64ArrayToQuadraticExtensionArray(openingSetRaw.QuotientPolys),
	}
}

func DeserializeFriProof(openingProofRaw types.OpeningProof) FriProof {
	var openingProof FriProof
	openingProof.PowWitness = gl.NewVariable(openingProofRaw.PowWitness)
	openingProof.FinalPoly.Coeffs = gl.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.FinalPoly.Coeffs)

	openingProof.CommitPhaseMerkleCaps = make([]FriMerkleCap, len(openingProofRaw.CommitPhaseMerkleCaps))
	for i := 0; i < len(openingProofRaw.CommitPhaseMerkleCaps); i++ {
		openingProof.CommitPhaseMerkleCaps[i] = HashesToVars(openingProofRaw.CommitPhaseMerkleCaps[i])
	}

	numQueryRoundProofs := len(openingProofRaw.QueryRoundProofs)
	openingProof.QueryRoundProofs = make([]FriQueryRound, numQueryRoundProofs)

	for i := 0; i < numQueryRoundProofs; i++ {
		numEvalProofs := len(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs)
		openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs = make([]FriEvalProof, numEvalProofs)
		for j := 0; j < numEvalProofs; j++ {
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].Elements = gl.Uint64ArrayToVariableArray(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].LeafElements)
			openingProof.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].MerkleProof.Siblings = HashesToVars(openingProofRaw.QueryRoundProofs[i].InitialTreesProof.EvalsProofs[j].MerkleProof.Hash)
		}

		numSteps := len(openingProofRaw.QueryRoundProofs[i].Steps)
		openingProof.QueryRoundProofs[i].Steps = make([]FriQueryStep, numSteps)
		for j := 0; j < numSteps; j++ {
			openingProof.QueryRoundProofs[i].Steps[j].Evals = gl.Uint64ArrayToQuadraticExtensionArray(openingProofRaw.QueryRoundProofs[i].Steps[j].Evals)
			openingProof.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings = HashesToVars(openingProofRaw.QueryRoundProofs[i].Steps[j].MerkleProof.Siblings)
		}
	}

	return openingProof
}

func DeserializeProofWithPublicInputs(raw types.ProofWithPublicInputsRaw) ProofWithPublicInputs {
	var proofWithPis ProofWithPublicInputs
	proofWithPis.Proof.WiresCap = DeserializeMerkleCap(raw.Proof.WiresCap)
	proofWithPis.Proof.PlonkZsPartialProductsCap = DeserializeMerkleCap(raw.Proof.PlonkZsPartialProductsCap)
	proofWithPis.Proof.QuotientPolysCap = DeserializeMerkleCap(raw.Proof.QuotientPolysCap)
	proofWithPis.Proof.Openings = DeserializeOpeningSet(struct {
		Constants       [][]uint64
		PlonkSigmas     [][]uint64
		Wires           [][]uint64
		PlonkZs         [][]uint64
		PlonkZsNext     [][]uint64
		PartialProducts [][]uint64
		QuotientPolys   [][]uint64
	}(raw.Proof.Openings))
	proofWithPis.Proof.OpeningProof = DeserializeFriProof(raw.Proof.OpeningProof)
	proofWithPis.PublicInputs = gl.Uint64ArrayToVariableArray(raw.PublicInputs)

	return proofWithPis
}

func DeserializeVerifierOnlyCircuitData(raw types.VerifierOnlyCircuitDataRaw) VerifierOnlyCircuitData {
	var verifierOnlyCircuitData VerifierOnlyCircuitData
	verifierOnlyCircuitData.ConstantSigmasCap = DeserializeMerkleCap(raw.ConstantsSigmasCap)
	verifierOnlyCircuitData.CircuitDigest = HashToVar(raw.CircuitDigest)
	return verifierOnlyCircuitData
}
