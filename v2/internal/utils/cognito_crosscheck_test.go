package utils

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// This test pins the SRP key derivation to a reference value independently computed with the
// pycognito Python library, using the same fixed inputs (including a fixed secret 'a', so the
// derived key is deterministic). It guards against regressions in the hand-rolled SRP math.

const (
	crossCheckPoolId   = "us-east-1_ABCDEFGHI"
	crossCheckUsername = "testuser"
	crossCheckPassword = "Test-Password-1!"
	crossCheckSmallA   = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	crossCheckSalt     = "beefcafe"
	crossCheckB        = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	// Reference value produced by pycognito for the inputs above.
	crossCheckExpectedKey = "7014993383843536a3db161060f58c90"
)

func TestCognitoSrpKeyDerivationMatchesPycognito(t *testing.T) {
	client, err := NewCognitoSrpClient(crossCheckPoolId)
	if err != nil {
		t.Fatal(err)
	}

	smallA, _ := new(big.Int).SetString(crossCheckSmallA, 16)
	client.smallA = smallA
	client.largeAHex = bigToHex(new(big.Int).Exp(client.g, smallA, client.bigN))

	bigB := hexToBig(crossCheckB)
	key := client.derivePasswordAuthenticationKey(crossCheckUsername, crossCheckPassword, bigB, crossCheckSalt)
	got := hex.EncodeToString(key)

	if got != crossCheckExpectedKey {
		t.Fatalf("derived key mismatch:\n got %s\nwant %s", got, crossCheckExpectedKey)
	}
}
