package recovery

import (
	"os"
	"testing"

	"github.com/SxMShaDoW/Vultisig-Share-Decoder/internal/vault"
)

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return data
}

func TestRecoverDKLS(t *testing.T) {
	inputs := []vault.FileInput{
		{Name: "TestDKLS1of2.vult", Content: readTestFile(t, "../../testdata/TestDKLS1of2.vult")},
		{Name: "TestDKLS2of2.vult", Content: readTestFile(t, "../../testdata/TestDKLS2of2.vult")},
	}

	result, err := Recover(inputs, []string{"", ""}, "dkls")
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}
	if result.Scheme != "dkls" {
		t.Errorf("scheme mismatch: %s", result.Scheme)
	}

	if result.PublicKeys.ECDSA != "0333e3d4df9cc071be24fd6c995421036074a1a88e5d3e0bc211b7ef4330078d9b" {
		t.Errorf("ECDSA pubkey mismatch: %s", result.PublicKeys.ECDSA)
	}
	if result.PublicKeys.EdDSA != "5e5ce6316a1047af3bcb228ac4f8d04ef718a9a0d6463fa6d2f62817939ccfe9" {
		t.Errorf("EdDSA pubkey mismatch: %s", result.PublicKeys.EdDSA)
	}

	var btcAddr, ethAddr string
	for _, k := range result.ECDSAKeys {
		if k.Name == "bitcoin" {
			btcAddr = k.Address
		}
		if k.Name == "ethereum" {
			ethAddr = k.Address
		}
	}
	if btcAddr != "bc1q0pap5flkh45w8zz2ew9xpf884me55g65l7vqcu" {
		t.Errorf("BTC address mismatch: %s", btcAddr)
	}
	if ethAddr != "0x60790246e37D154e02beaF2b9Fb27F93a26A6B3f" {
		t.Errorf("ETH address mismatch: %s", ethAddr)
	}

	var solAddr string
	for _, k := range result.EdDSAKeys {
		if k.Name == "solana" {
			solAddr = k.Address
		}
	}
	if solAddr != "7MMV5XnYP2ZT5AuXFuaH1Yt3Hv4X4gMYiZkA7vBUFiN4" {
		t.Errorf("solana address mismatch: %s", solAddr)
	}
}

func TestRecoverGG20Honeypot(t *testing.T) {
	inputs := []vault.FileInput{
		{Name: "honeypot.bak", Content: readTestFile(t, "../../testdata/honeypot.bak")},
	}

	result, err := Recover(inputs, []string{""}, "gg20")
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}
	if result.Scheme != "gg20" {
		t.Errorf("scheme mismatch: %s", result.Scheme)
	}
	if result.RootKeyInfo == nil {
		t.Fatal("root key info is nil")
	}
	if len(result.ECDSAKeys) == 0 {
		t.Fatal("expected ECDSA keys")
	}
}

func TestRecoverGG20TwoShare(t *testing.T) {
	inputs := []vault.FileInput{
		{Name: "part1.vult", Content: readTestFile(t, "../../testdata/Test-part1of2.vult")},
		{Name: "part2.vult", Content: readTestFile(t, "../../testdata/Test-part2of2.vult")},
	}

	result, err := Recover(inputs, []string{"", ""}, "gg20")
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.Error)
	}
	if len(result.ECDSAKeys) == 0 {
		t.Fatal("expected ECDSA keys")
	}
	if len(result.EdDSAKeys) == 0 {
		t.Fatal("expected EdDSA keys")
	}

	var solAddr string
	for _, k := range result.EdDSAKeys {
		if k.Name == "solana" {
			solAddr = k.Address
		}
	}
	if solAddr != "EPEg1C2pEwiEbPaBTuyydnvGpZoa6y3iXVVNzv7JYT8H" {
		t.Errorf("GG20 solana address mismatch: %s", solAddr)
	}
}

func TestRecoverAutoDetectsDKLS(t *testing.T) {
	inputs := []vault.FileInput{
		{Name: "TestDKLS1of2.vult", Content: readTestFile(t, "../../testdata/TestDKLS1of2.vult")},
		{Name: "TestDKLS2of2.vult", Content: readTestFile(t, "../../testdata/TestDKLS2of2.vult")},
	}

	result, err := Recover(inputs, []string{"", ""}, "auto")
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}

	if result.Scheme != "dkls" {
		t.Errorf("expected auto-detection to choose dkls, got: %s", result.Scheme)
	}
}

func TestRecoverAutoDetectsGG20(t *testing.T) {
	inputs := []vault.FileInput{
		{Name: "honeypot.bak", Content: readTestFile(t, "../../testdata/honeypot.bak")},
	}

	result, err := Recover(inputs, []string{""}, "auto")
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}

	if result.Scheme != "gg20" {
		t.Errorf("expected auto-detection to choose gg20, got: %s", result.Scheme)
	}
}
