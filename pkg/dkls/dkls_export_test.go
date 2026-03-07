package dkls

import (
	"encoding/hex"
	"testing"

	"main/pkg/fileutils"
	"main/pkg/types"
)

func TestExportPrivateKeyWithTestFiles(t *testing.T) {
	file1, err := fileutils.ReadFileContent("../../TestDKLS1of2.vult")
	if err != nil {
		t.Fatalf("failed to read TestDKLS1of2.vult: %v", err)
	}
	file2, err := fileutils.ReadFileContent("../../TestDKLS2of2.vult")
	if err != nil {
		t.Fatalf("failed to read TestDKLS2of2.vult: %v", err)
	}

	fileInfos := []types.FileInfo{
		{Name: "TestDKLS1of2.vult", Content: file1},
		{Name: "TestDKLS2of2.vult", Content: file2},
	}
	passwords := []string{"", ""}
	source := types.CommandLine

	keyshareDataList, partyIDs, err := ExtractDKLSKeyshares(fileInfos, passwords, source)
	if err != nil {
		t.Fatalf("failed to extract keyshares: %v", err)
	}

	if len(keyshareDataList) != 2 {
		t.Fatalf("expected 2 keyshares, got %d", len(keyshareDataList))
	}
	if len(partyIDs) != 2 {
		t.Fatalf("expected 2 party IDs, got %d", len(partyIDs))
	}

	result, err := ExportPrivateKey(keyshareDataList, partyIDs)
	if err != nil {
		t.Fatalf("failed to export private key: %v", err)
	}

	if len(result.PrivateKey) != 32 {
		t.Errorf("expected 32-byte private key, got %d bytes", len(result.PrivateKey))
	}
	if len(result.PublicKey) != 33 {
		t.Errorf("expected 33-byte compressed public key, got %d bytes", len(result.PublicKey))
	}
	if len(result.ChainCode) != 32 {
		t.Errorf("expected 32-byte chain code, got %d bytes", len(result.ChainCode))
	}

	expectedPrivKey := "0806a352d32950671e711225514a5fd53d6411dc9f4525d7bad11ef73956c601"
	actualPrivKey := hex.EncodeToString(result.PrivateKey)
	if actualPrivKey != expectedPrivKey {
		t.Errorf("private key mismatch\nexpected: %s\n  actual: %s", expectedPrivKey, actualPrivKey)
	}

	expectedPubKey := "0333e3d4df9cc071be24fd6c995421036074a1a88e5d3e0bc211b7ef4330078d9b"
	actualPubKey := hex.EncodeToString(result.PublicKey)
	if actualPubKey != expectedPubKey {
		t.Errorf("public key mismatch\nexpected: %s\n  actual: %s", expectedPubKey, actualPubKey)
	}

	expectedChainCode := "e2f8c4826d6d23407cff45498b940f52756c3056fa1bcba0cb7f6bafc2478eac"
	actualChainCode := hex.EncodeToString(result.ChainCode)
	if actualChainCode != expectedChainCode {
		t.Errorf("chain code mismatch\nexpected: %s\n  actual: %s", expectedChainCode, actualChainCode)
	}
}

func TestExportEdDSAPrivateKeyWithTestFiles(t *testing.T) {
	file1, err := fileutils.ReadFileContent("../../TestDKLS1of2.vult")
	if err != nil {
		t.Fatalf("failed to read TestDKLS1of2.vult: %v", err)
	}
	file2, err := fileutils.ReadFileContent("../../TestDKLS2of2.vult")
	if err != nil {
		t.Fatalf("failed to read TestDKLS2of2.vult: %v", err)
	}

	fileInfos := []types.FileInfo{
		{Name: "TestDKLS1of2.vult", Content: file1},
		{Name: "TestDKLS2of2.vult", Content: file2},
	}

	vaultKeyshares, err := ExtractAllKeyshares(fileInfos, []string{"", ""}, types.CommandLine)
	if err != nil {
		t.Fatalf("failed to extract keyshares: %v", err)
	}

	if len(vaultKeyshares.EdDSAKeyshares) != 2 {
		t.Fatalf("expected 2 EdDSA keyshares, got %d", len(vaultKeyshares.EdDSAKeyshares))
	}

	result, err := ExportEdDSAPrivateKey(vaultKeyshares.EdDSAKeyshares, vaultKeyshares.PartyIDs)
	if err != nil {
		t.Fatalf("failed to export EdDSA private key: %v", err)
	}

	if len(result.PrivateKey) != 32 {
		t.Errorf("expected 32-byte EdDSA private key, got %d bytes", len(result.PrivateKey))
	}
	if len(result.PublicKey) != 32 {
		t.Errorf("expected 32-byte EdDSA public key, got %d bytes", len(result.PublicKey))
	}

	expectedPubKey := "20e368bf985efdc270500c6e9dc1159102323ff6eabab56f8fa9798e4ac0e2a9"
	actualPubKey := hex.EncodeToString(result.PublicKey)
	if actualPubKey != expectedPubKey {
		t.Errorf("EdDSA public key mismatch\nexpected: %s\n  actual: %s", expectedPubKey, actualPubKey)
	}

	expectedPrivKey := "733da00cb116e47317d8d0fdf2629f11500abd28a52a8dcbb3f8737f2a631e07"
	actualPrivKey := hex.EncodeToString(result.PrivateKey)
	if actualPrivKey != expectedPrivKey {
		t.Errorf("EdDSA private key mismatch\nexpected: %s\n  actual: %s", expectedPrivKey, actualPrivKey)
	}
}

func TestExportPrivateKeyInsufficientShares(t *testing.T) {
	_, err := ExportPrivateKey([][]byte{[]byte("single")}, []string{"p1"})
	if err == nil {
		t.Fatal("expected error for single keyshare")
	}
}

func TestExportPrivateKeyMismatchedCounts(t *testing.T) {
	_, err := ExportPrivateKey([][]byte{[]byte("a"), []byte("b")}, []string{"p1"})
	if err == nil {
		t.Fatal("expected error for mismatched counts")
	}
}

func TestExtractDKLSKeysharesInsufficientFiles(t *testing.T) {
	fileInfos := []types.FileInfo{
		{Name: "single.vult", Content: []byte("test")},
	}
	_, _, err := ExtractDKLSKeyshares(fileInfos, []string{""}, types.CommandLine)
	if err == nil {
		t.Fatal("expected error for single file")
	}
}
