package output

import (
	"encoding/hex"
	"testing"
)

func TestBuildRootKeyInfo(t *testing.T) {
	privKeyBytes, _ := hex.DecodeString("0806a352d32950671e711225514a5fd53d6411dc9f4525d7bad11ef73956c601")
	chainCodeBytes, _ := hex.DecodeString("e2f8c4826d6d23407cff45498b940f52756c3056fa1bcba0cb7f6bafc2478eac")

	info := BuildRootKeyInfo(privKeyBytes, chainCodeBytes)

	expectedPubKey := "0333e3d4df9cc071be24fd6c995421036074a1a88e5d3e0bc211b7ef4330078d9b"
	if info.HexPubKeyECDSA != expectedPubKey {
		t.Errorf("public key mismatch\nexpected: %s\n  actual: %s", expectedPubKey, info.HexPubKeyECDSA)
	}

	if info.ChainCode != "e2f8c4826d6d23407cff45498b940f52756c3056fa1bcba0cb7f6bafc2478eac" {
		t.Errorf("chain code mismatch")
	}

	if info.ExtendedPrivKey == "" {
		t.Error("extended private key should not be empty")
	}
}

func TestBuildECDSACoinKeys(t *testing.T) {
	privKeyBytes, _ := hex.DecodeString("0806a352d32950671e711225514a5fd53d6411dc9f4525d7bad11ef73956c601")
	chainCodeBytes, _ := hex.DecodeString("e2f8c4826d6d23407cff45498b940f52756c3056fa1bcba0cb7f6bafc2478eac")

	keys, err := BuildECDSACoinKeys(privKeyBytes, chainCodeBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(keys) == 0 {
		t.Fatal("expected at least one coin key")
	}

	var btcKey *CoinKeyInfo
	var ethKey *CoinKeyInfo
	for i := range keys {
		if keys[i].Name == "bitcoin" {
			btcKey = &keys[i]
		}
		if keys[i].Name == "ethereum" {
			ethKey = &keys[i]
		}
	}

	if btcKey == nil {
		t.Fatal("expected bitcoin key")
	}
	if btcKey.Address != "bc1q0pap5flkh45w8zz2ew9xpf884me55g65l7vqcu" {
		t.Errorf("bitcoin address mismatch: %s", btcKey.Address)
	}

	if ethKey == nil {
		t.Fatal("expected ethereum key")
	}
	if ethKey.Address != "0x60790246e37D154e02beaF2b9Fb27F93a26A6B3f" {
		t.Errorf("ethereum address mismatch: %s", ethKey.Address)
	}
	if ethKey.HexPrivateKey != "e49960641cf0f56139fe8a3088cf7bf8bb0d4bb9ee94b788875834d604703623" {
		t.Errorf("ethereum private key mismatch: %s", ethKey.HexPrivateKey)
	}
}

func TestBuildEdDSACoinKeys(t *testing.T) {
	privKeyBytes, _ := hex.DecodeString("733da00cb116e47317d8d0fdf2629f11500abd28a52a8dcbb3f8737f2a631e07")
	pubKeyBytes, _ := hex.DecodeString("20e368bf985efdc270500c6e9dc1159102323ff6eabab56f8fa9798e4ac0e2a9")

	keys, err := BuildEdDSACoinKeys(privKeyBytes, pubKeyBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(keys) != 3 {
		t.Fatalf("expected 3 EdDSA coin keys (solana, sui, ton), got %d", len(keys))
	}

	var solKey *CoinKeyInfo
	for i := range keys {
		if keys[i].Name == "solana" {
			solKey = &keys[i]
		}
	}

	if solKey == nil {
		t.Fatal("expected solana key")
	}
	if solKey.Address != "3DPAkfuk5bkh1c1Pg5GN57Gr6cSJsZHVBcJLTFMapmA8" {
		t.Errorf("solana address mismatch: %s", solKey.Address)
	}
}
