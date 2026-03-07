package dkls

import (
	"fmt"

	session "github.com/vultisig/go-wrappers/go-schnorr/sessions"
)

func ExportEdDSAPrivateKey(keyshareDataList [][]byte, partyIDs []string) (*ExportResult, error) {
	if len(keyshareDataList) < 2 {
		return nil, fmt.Errorf("at least 2 EdDSA keyshares are required, got %d", len(keyshareDataList))
	}
	if len(keyshareDataList) != len(partyIDs) {
		return nil, fmt.Errorf("keyshare count (%d) must match party ID count (%d)", len(keyshareDataList), len(partyIDs))
	}

	firstHandle, err := session.SchnorrKeyshareFromBytes(keyshareDataList[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse first EdDSA keyshare: %w", err)
	}

	publicKey, err := session.SchnorrKeysharePublicKey(firstHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get EdDSA public key: %w", err)
	}

	exportSession, setupMsg, err := session.SchnorrKeyExportReceiverNew(firstHandle, partyIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to create Schnorr export receiver session: %w", err)
	}

	msgs := make([][]byte, 0, len(keyshareDataList)-1)
	for idx, data := range keyshareDataList[1:] {
		handle, err := session.SchnorrKeyshareFromBytes(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EdDSA keyshare %d: %w", idx+1, err)
		}

		msg, _, err := session.SchnorrKeyExporter(handle, partyIDs[idx+1], setupMsg)
		if err != nil {
			return nil, fmt.Errorf("failed to export EdDSA keyshare %d: %w", idx+1, err)
		}
		msgs = append(msgs, msg)
	}

	var privateKey []byte
	for i, msg := range msgs {
		finished, err := session.SchnorrKeyExportReceiverInputMessage(exportSession, msg)
		if err != nil {
			return nil, fmt.Errorf("failed to input EdDSA message %d: %w", i, err)
		}
		if finished {
			privateKey, err = session.SchnorrKeyExportReceiverFinish(exportSession)
			if err != nil {
				return nil, fmt.Errorf("failed to finish EdDSA export: %w", err)
			}
			break
		}
	}

	if privateKey == nil {
		return nil, fmt.Errorf("EdDSA key export did not complete after processing all messages")
	}

	return &ExportResult{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}
