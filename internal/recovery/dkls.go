//go:build !wasm

package recovery

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	dklsSession "github.com/vultisig/go-wrappers/go-dkls/sessions"
	schnorrSession "github.com/vultisig/go-wrappers/go-schnorr/sessions"

	"github.com/SxMShaDoW/Vultisig-Share-Decoder/internal/derive"
	"github.com/SxMShaDoW/Vultisig-Share-Decoder/internal/vault"
)

type dklsKeyshares struct {
	ECDSAKeyshares [][]byte
	EdDSAKeyshares [][]byte
	PartyIDs       []string
}

type exportResult struct {
	PrivateKey []byte
	PublicKey  []byte
	ChainCode  []byte
}

func recoverDKLS(inputs []vault.FileInput, passwords []string) (*RecoveryResult, error) {
	result := &RecoveryResult{
		Success:   true,
		Scheme:    "dkls",
		ECDSAKeys: make([]derive.CoinKey, 0),
		EdDSAKeys: make([]derive.CoinKey, 0),
	}

	keyshares, err := extractDKLSKeyshares(inputs, passwords)
	if err != nil {
		return nil, err
	}

	for i, partyID := range keyshares.PartyIDs {
		result.ShareDetails = append(result.ShareDetails, ShareDetail{
			BackupName: inputs[i].Name,
			ThisShare:  partyID,
			AllShares:  keyshares.PartyIDs,
		})
	}

	ecdsaResult, err := exportECDSAKey(keyshares.ECDSAKeyshares, keyshares.PartyIDs)
	if err != nil {
		return nil, fmt.Errorf("ECDSA key export failed: %w", err)
	}

	pubKeyHex := hex.EncodeToString(ecdsaResult.PublicKey)

	net := &chaincfg.MainNetParams
	extKey := hdkeychain.NewExtendedKey(
		net.HDPrivateKeyID[:],
		ecdsaResult.PrivateKey,
		ecdsaResult.ChainCode,
		[]byte{0x00, 0x00, 0x00, 0x00},
		0, 0, true,
	)

	result.RootKeyInfo = &RootKeyInfo{
		HexPubKeyECDSA:  pubKeyHex,
		HexPrivKeyECDSA: hex.EncodeToString(ecdsaResult.PrivateKey),
		ChainCode:       hex.EncodeToString(ecdsaResult.ChainCode),
		ExtendedPrivKey: extKey.String(),
	}
	result.PublicKeys.ECDSA = pubKeyHex

	ecdsaKeys, err := derive.DeriveECDSACoins(ecdsaResult.PrivateKey, ecdsaResult.ChainCode)
	if err == nil {
		result.ECDSAKeys = ecdsaKeys
	}

	if len(keyshares.EdDSAKeyshares) >= 2 {
		eddsaResult, err := exportEdDSAKey(keyshares.EdDSAKeyshares, keyshares.PartyIDs)
		if err == nil {
			scalarBytes := reduceEdDSAScalar(eddsaResult.PrivateKey)
			privKey, pubKey, err := edwards.PrivKeyFromScalar(scalarBytes)
			if err == nil {
				privKeyBytes := privKey.Serialize()
				pubKeyBytes := pubKey.Serialize()
				eddsaPubHex := hex.EncodeToString(pubKeyBytes)
				eddsaPrivHex := hex.EncodeToString(privKeyBytes)
				result.PublicKeys.EdDSA = eddsaPubHex
				result.RootKeyInfo.HexPubKeyEdDSA = eddsaPubHex
				result.RootKeyInfo.HexPrivKeyEdDSA = eddsaPrivHex
				eddsaKeys, err := derive.DeriveEdDSACoins(privKeyBytes, pubKeyBytes)
				if err == nil {
					result.EdDSAKeys = eddsaKeys
				}
			}
		}
	}

	return result, nil
}

func extractDKLSKeyshares(inputs []vault.FileInput, passwords []string) (*dklsKeyshares, error) {
	if len(inputs) < 2 {
		return nil, fmt.Errorf("DKLS requires at least 2 keyshare files, got %d", len(inputs))
	}

	ks := &dklsKeyshares{
		ECDSAKeyshares: make([][]byte, 0, len(inputs)),
		EdDSAKeyshares: make([][]byte, 0, len(inputs)),
		PartyIDs:       make([]string, 0, len(inputs)),
	}

	for i, input := range inputs {
		password := ""
		if i < len(passwords) {
			password = passwords[i]
		}

		v, err := vault.ParseVaultFromFile(input.Content, input.Name, password, vault.CommandLine)
		if err != nil {
			return nil, fmt.Errorf("failed to parse vault file %s: %w", input.Name, err)
		}

		if len(v.KeyShares) == 0 {
			return nil, fmt.Errorf("no keyshares found in vault file %s", input.Name)
		}

		ecdsaBytes, err := decodeKeyshare(v.KeyShares[0].Keyshare)
		if err != nil {
			return nil, fmt.Errorf("failed to decode ECDSA keyshare from %s: %w", input.Name, err)
		}
		ks.ECDSAKeyshares = append(ks.ECDSAKeyshares, ecdsaBytes)

		if len(v.KeyShares) > 1 && v.KeyShares[1].Keyshare != "" {
			eddsaBytes, err := decodeKeyshare(v.KeyShares[1].Keyshare)
			if err != nil {
				return nil, fmt.Errorf("failed to decode EdDSA keyshare from %s: %w", input.Name, err)
			}
			ks.EdDSAKeyshares = append(ks.EdDSAKeyshares, eddsaBytes)
		}

		if v.LocalPartyId == "" {
			return nil, fmt.Errorf("no party ID found in vault file %s", input.Name)
		}
		ks.PartyIDs = append(ks.PartyIDs, v.LocalPartyId)
	}

	return ks, nil
}

func exportECDSAKey(keyshareDataList [][]byte, partyIDs []string) (*exportResult, error) {
	if len(keyshareDataList) < 2 {
		return nil, fmt.Errorf("at least 2 keyshares are required, got %d", len(keyshareDataList))
	}
	if len(keyshareDataList) != len(partyIDs) {
		return nil, fmt.Errorf("keyshare count (%d) must match party ID count (%d)", len(keyshareDataList), len(partyIDs))
	}

	firstHandle, err := dklsSession.DklsKeyshareFromBytes(keyshareDataList[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse first keyshare: %w", err)
	}
	defer dklsSession.DklsKeyshareFree(firstHandle)

	publicKey, err := dklsSession.DklsKeysharePublicKey(firstHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	chainCode, err := dklsSession.DklsKeyshareChainCode(firstHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain code: %w", err)
	}

	exportSession, setupMsg, err := dklsSession.DklsKeyExportReceiverNew(firstHandle, partyIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to create export receiver session: %w", err)
	}

	msgs := make([][]byte, 0, len(keyshareDataList)-1)
	for idx, data := range keyshareDataList[1:] {
		handle, err := dklsSession.DklsKeyshareFromBytes(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse keyshare %d: %w", idx+1, err)
		}
		defer dklsSession.DklsKeyshareFree(handle)

		msg, _, err := dklsSession.DklsKeyExporter(handle, partyIDs[idx+1], setupMsg)
		if err != nil {
			return nil, fmt.Errorf("failed to export keyshare %d: %w", idx+1, err)
		}
		msgs = append(msgs, msg)
	}

	var privateKey []byte
	for i, msg := range msgs {
		finished, err := dklsSession.DklsKeyExportReceiverInputMessage(exportSession, msg)
		if err != nil {
			return nil, fmt.Errorf("failed to input message %d: %w", i, err)
		}
		if finished {
			privateKey, err = dklsSession.DklsKeyExportReceiverFinish(exportSession)
			if err != nil {
				return nil, fmt.Errorf("failed to finish export: %w", err)
			}
			break
		}
	}

	if privateKey == nil {
		return nil, fmt.Errorf("key export did not complete after processing all messages")
	}

	return &exportResult{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		ChainCode:  chainCode,
	}, nil
}

func exportEdDSAKey(keyshareDataList [][]byte, partyIDs []string) (*exportResult, error) {
	if len(keyshareDataList) < 2 {
		return nil, fmt.Errorf("at least 2 EdDSA keyshares are required, got %d", len(keyshareDataList))
	}
	if len(keyshareDataList) != len(partyIDs) {
		return nil, fmt.Errorf("keyshare count (%d) must match party ID count (%d)", len(keyshareDataList), len(partyIDs))
	}

	firstHandle, err := schnorrSession.SchnorrKeyshareFromBytes(keyshareDataList[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse first EdDSA keyshare: %w", err)
	}

	publicKey, err := schnorrSession.SchnorrKeysharePublicKey(firstHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get EdDSA public key: %w", err)
	}

	exportSession, setupMsg, err := schnorrSession.SchnorrKeyExportReceiverNew(firstHandle, partyIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to create Schnorr export receiver session: %w", err)
	}

	msgs := make([][]byte, 0, len(keyshareDataList)-1)
	for idx, data := range keyshareDataList[1:] {
		handle, err := schnorrSession.SchnorrKeyshareFromBytes(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EdDSA keyshare %d: %w", idx+1, err)
		}

		msg, _, err := schnorrSession.SchnorrKeyExporter(handle, partyIDs[idx+1], setupMsg)
		if err != nil {
			return nil, fmt.Errorf("failed to export EdDSA keyshare %d: %w", idx+1, err)
		}
		msgs = append(msgs, msg)
	}

	var privateKey []byte
	for i, msg := range msgs {
		finished, err := schnorrSession.SchnorrKeyExportReceiverInputMessage(exportSession, msg)
		if err != nil {
			return nil, fmt.Errorf("failed to input EdDSA message %d: %w", i, err)
		}
		if finished {
			privateKey, err = schnorrSession.SchnorrKeyExportReceiverFinish(exportSession)
			if err != nil {
				return nil, fmt.Errorf("failed to finish EdDSA export: %w", err)
			}
			break
		}
	}

	if privateKey == nil {
		return nil, fmt.Errorf("EdDSA key export did not complete after processing all messages")
	}

	return &exportResult{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

var ed25519Order, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

func reduceEdDSAScalar(raw []byte) []byte {
	scalar := new(big.Int).SetBytes(raw)
	if scalar.Cmp(ed25519Order) >= 0 {
		scalar.Mod(scalar, ed25519Order)
	}
	reduced := scalar.Bytes()
	var buf [32]byte
	copy(buf[32-len(reduced):], reduced)
	return buf[:]
}

func decodeKeyshare(keyshareStr string) ([]byte, error) {
	trimmed := strings.TrimSpace(keyshareStr)

	if isHexString(trimmed) {
		decoded, err := hex.DecodeString(trimmed)
		if err == nil && len(decoded) > 100 {
			return decoded, nil
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil && len(decoded) > 100 {
		return decoded, nil
	}

	decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
	if err == nil && len(decoded) > 100 {
		return decoded, nil
	}

	return nil, fmt.Errorf("keyshare string could not be decoded as hex or base64 (length: %d)", len(trimmed))
}

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0 && len(s)%2 == 0
}
