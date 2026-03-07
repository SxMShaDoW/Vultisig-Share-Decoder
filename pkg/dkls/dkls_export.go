package dkls

import (
	"fmt"

	session "github.com/vultisig/go-wrappers/go-dkls/sessions"
)

type ExportResult struct {
	PrivateKey []byte
	PublicKey  []byte
	ChainCode  []byte
}

// ExportPrivateKey takes raw keyshare bytes and party IDs, performs the DKLS key export protocol,
// and returns the reconstructed private key material.
func ExportPrivateKey(keyshareDataList [][]byte, partyIDs []string) (*ExportResult, error) {
	if len(keyshareDataList) < 2 {
		return nil, fmt.Errorf("at least 2 keyshares are required, got %d", len(keyshareDataList))
	}
	if len(keyshareDataList) != len(partyIDs) {
		return nil, fmt.Errorf("keyshare count (%d) must match party ID count (%d)", len(keyshareDataList), len(partyIDs))
	}

	firstHandle, err := session.DklsKeyshareFromBytes(keyshareDataList[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse first keyshare: %w", err)
	}
	defer session.DklsKeyshareFree(firstHandle)

	publicKey, err := session.DklsKeysharePublicKey(firstHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	chainCode, err := session.DklsKeyshareChainCode(firstHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain code: %w", err)
	}

	exportSession, setupMsg, err := session.DklsKeyExportReceiverNew(firstHandle, partyIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to create export receiver session: %w", err)
	}

	msgs := make([][]byte, 0, len(keyshareDataList)-1)
	for idx, data := range keyshareDataList[1:] {
		handle, err := session.DklsKeyshareFromBytes(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse keyshare %d: %w", idx+1, err)
		}
		defer session.DklsKeyshareFree(handle)

		msg, _, err := session.DklsKeyExporter(handle, partyIDs[idx+1], setupMsg)
		if err != nil {
			return nil, fmt.Errorf("failed to export keyshare %d: %w", idx+1, err)
		}
		msgs = append(msgs, msg)
	}

	var privateKey []byte
	for i, msg := range msgs {
		finished, err := session.DklsKeyExportReceiverInputMessage(exportSession, msg)
		if err != nil {
			return nil, fmt.Errorf("failed to input message %d: %w", i, err)
		}
		if finished {
			privateKey, err = session.DklsKeyExportReceiverFinish(exportSession)
			if err != nil {
				return nil, fmt.Errorf("failed to finish export: %w", err)
			}
			break
		}
	}

	if privateKey == nil {
		return nil, fmt.Errorf("key export did not complete after processing all messages")
	}

	return &ExportResult{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		ChainCode:  chainCode,
	}, nil
}
