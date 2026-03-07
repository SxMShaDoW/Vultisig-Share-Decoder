package derive

import (
	"encoding/hex"
	"testing"
)

func TestDeriveECDSACoins(t *testing.T) {
	privKeyBytes, _ := hex.DecodeString("0806a352d32950671e711225514a5fd53d6411dc9f4525d7bad11ef73956c601")
	chainCodeBytes, _ := hex.DecodeString("e2f8c4826d6d23407cff45498b940f52756c3056fa1bcba0cb7f6bafc2478eac")

	keys, err := DeriveECDSACoins(privKeyBytes, chainCodeBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(keys) == 0 {
		t.Fatal("expected at least one coin key")
	}

	expected := map[string]string{
		"bitcoin":  "bc1q0pap5flkh45w8zz2ew9xpf884me55g65l7vqcu",
		"ethereum": "0x60790246e37D154e02beaF2b9Fb27F93a26A6B3f",
	}

	byName := map[string]CoinKey{}
	for _, k := range keys {
		byName[k.Name] = k
	}

	for coin, wantAddr := range expected {
		got, ok := byName[coin]
		if !ok {
			t.Fatalf("missing coin: %s", coin)
		}
		if got.Address != wantAddr {
			t.Errorf("%s address mismatch: want %s, got %s", coin, wantAddr, got.Address)
		}
	}

	btc := byName["bitcoin"]
	if btc.WIFPrivateKey == "" {
		t.Error("bitcoin WIF should not be empty")
	}

	eth := byName["ethereum"]
	if eth.HexPrivateKey != "e49960641cf0f56139fe8a3088cf7bf8bb0d4bb9ee94b788875834d604703623" {
		t.Errorf("ethereum private key mismatch: %s", eth.HexPrivateKey)
	}
}

func TestDeriveEdDSACoins(t *testing.T) {
	privKeyBytes, _ := hex.DecodeString("733da00cb116e47317d8d0fdf2629f11500abd28a52a8dcbb3f8737f2a631e07")
	pubKeyBytes, _ := hex.DecodeString("20e368bf985efdc270500c6e9dc1159102323ff6eabab56f8fa9798e4ac0e2a9")

	keys, err := DeriveEdDSACoins(privKeyBytes, pubKeyBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(keys) != 3 {
		t.Fatalf("expected 3 EdDSA coin keys, got %d", len(keys))
	}

	byName := map[string]CoinKey{}
	for _, k := range keys {
		byName[k.Name] = k
	}

	sol := byName["solana"]
	if sol.Address != "3DPAkfuk5bkh1c1Pg5GN57Gr6cSJsZHVBcJLTFMapmA8" {
		t.Errorf("solana address mismatch: %s", sol.Address)
	}
}

func TestCosmosAddress(t *testing.T) {
	pubKeyBytes, _ := hex.DecodeString("0320ecd7f07520ee899241ac6459cfc462bc37569c5b00b71508b64c9eca6998a1")

	tests := []struct {
		hrp  string
		want string
	}{
		{"thor", "thor167h7nq5wuklekdeyrmsgy2p6gc3acaezp0wwql"},
		{"maya", "maya167h7nq5wuklekdeyrmsgy2p6gc3acaezpcszk0"},
	}

	for _, tt := range tests {
		addr, err := cosmosAddress(pubKeyBytes, tt.hrp)
		if err != nil {
			t.Fatalf("cosmosAddress(%s) error: %v", tt.hrp, err)
		}
		if addr != tt.want {
			t.Errorf("cosmosAddress(%s) = %s, want %s", tt.hrp, addr, tt.want)
		}
	}
}
