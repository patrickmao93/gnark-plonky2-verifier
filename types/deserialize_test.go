package types

import (
	"testing"
)

func TestReadProofWithPublicInputs(t *testing.T) {
	ReadProofWithPublicInputs("../testdata/fib_small/proof_with_public_inputs.json")
}

func TestReadVerifierOnlyCircuitData(t *testing.T) {
	ReadVerifierOnlyCircuitData("../testdata/fib_small/verifier_only_circuit_data.json")
}
