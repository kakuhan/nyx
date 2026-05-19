package protocol

import (
	"encoding/hex"
	"testing"
)

// sharedSecretHex is a FIXED shared secret used by both FlClash and standalone
// Nyx cross-validation tests. DO NOT CHANGE.
const sharedSecretHex = "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef"

func TestCrossValidateDeriveBidirectionalKeys(t *testing.T) {
	sharedSecret, err := hex.DecodeString(sharedSecretHex)
	if err != nil {
		t.Fatalf("decode shared secret: %v", err)
	}

	clientKey, serverKey, err := DeriveBidirectionalKeys(sharedSecret)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	if len(clientKey) != 32 {
		t.Errorf("clientSendKey len = %d, want 32", len(clientKey))
	}
	if len(serverKey) != 32 {
		t.Errorf("serverSendKey len = %d, want 32", len(serverKey))
	}

	clientHex := hex.EncodeToString(clientKey)
	serverHex := hex.EncodeToString(serverKey)

	t.Logf("Nyx clientSendKey = %s", clientHex)
	t.Logf("Nyx serverSendKey = %s", serverHex)

	// Determinism check
	c2, s2, _ := DeriveBidirectionalKeys(sharedSecret)
	if hex.EncodeToString(c2) != clientHex || hex.EncodeToString(s2) != serverHex {
		t.Error("DeriveBidirectionalKeys is not deterministic")
	}
}
