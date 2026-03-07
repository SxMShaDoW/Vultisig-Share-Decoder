package format

import (
	"fmt"
	"strings"

	"github.com/SxMShaDoW/Vultisig-Share-Decoder/internal/recovery"
)

func Text(r *recovery.RecoveryResult) string {
	var b strings.Builder

	for _, share := range r.ShareDetails {
		fmt.Fprintf(&b, "Backup name: %s\n", share.BackupName)
		fmt.Fprintf(&b, "This Share: %s\n", share.ThisShare)
		fmt.Fprintf(&b, "All Shares: %v\n", share.AllShares)
	}

	fmt.Fprintf(&b, "\nScheme: %s\n", r.Scheme)

	if r.RootKeyInfo != nil {
		fmt.Fprintf(&b, "\n=== Root Key Info ===\n")
		fmt.Fprintf(&b, "ECDSA Public Key:  %s\n", r.RootKeyInfo.HexPubKeyECDSA)
		fmt.Fprintf(&b, "ECDSA Private Key: %s\n", r.RootKeyInfo.HexPrivKeyECDSA)
		fmt.Fprintf(&b, "Chain Code:        %s\n", r.RootKeyInfo.ChainCode)
		if r.RootKeyInfo.ExtendedPrivKey != "" {
			fmt.Fprintf(&b, "Extended Priv Key: %s\n", r.RootKeyInfo.ExtendedPrivKey)
		}
		if r.RootKeyInfo.HexPubKeyEdDSA != "" {
			fmt.Fprintf(&b, "EdDSA Public Key:  %s\n", r.RootKeyInfo.HexPubKeyEdDSA)
		}
		if r.RootKeyInfo.HexPrivKeyEdDSA != "" {
			fmt.Fprintf(&b, "EdDSA Private Key: %s\n", r.RootKeyInfo.HexPrivKeyEdDSA)
		}
	}

	if len(r.ECDSAKeys) > 0 {
		fmt.Fprintf(&b, "\n=== ECDSA Coins ===\n")
		for _, coin := range r.ECDSAKeys {
			fmt.Fprintf(&b, "\n--- %s (%s) ---\n", coin.Name, coin.DerivePath)
			fmt.Fprintf(&b, "Address:     %s\n", coin.Address)
			fmt.Fprintf(&b, "Private Key: %s\n", coin.HexPrivateKey)
			fmt.Fprintf(&b, "Public Key:  %s\n", coin.HexPublicKey)
			if coin.WIFPrivateKey != "" {
				fmt.Fprintf(&b, "WIF:         %s\n", coin.WIFPrivateKey)
			}
		}
	}

	if len(r.EdDSAKeys) > 0 {
		fmt.Fprintf(&b, "\n=== EdDSA Coins ===\n")
		for _, coin := range r.EdDSAKeys {
			fmt.Fprintf(&b, "\n--- %s (%s) ---\n", coin.Name, coin.DerivePath)
			fmt.Fprintf(&b, "Address:     %s\n", coin.Address)
			fmt.Fprintf(&b, "Private Key: %s\n", coin.HexPrivateKey)
			fmt.Fprintf(&b, "Public Key:  %s\n", coin.HexPublicKey)
		}
	}

	return b.String()
}
