package keyprocessing

import (
	"fmt"
	"strings"
	"main/pkg/dkls"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ProcessDKLSKeys processes DKLS scheme keys
func ProcessDKLSKeys(threshold int, dklsShares []dkls.DKLSShareData, partyIDs []string, outputBuilder *strings.Builder) error {
	fmt.Fprintf(outputBuilder, "\n=== DKLS Key Processing ===\n")
	fmt.Fprintf(outputBuilder, "Threshold: %d\n", threshold)
	fmt.Fprintf(outputBuilder, "Number of DKLS shares: %d\n", len(dklsShares))
	fmt.Fprintf(outputBuilder, "Party IDs: %v\n\n", partyIDs)

	// Initialize DKLS wrapper
	dklsWrapper := dkls.NewDKLSWrapper()
	if err := dklsWrapper.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize DKLS wrapper: %w", err)
	}

	// Validate shares
	if err := dklsWrapper.ValidateShares(dklsShares); err != nil {
		return fmt.Errorf("share validation failed: %w", err)
	}

	// For now, display the DKLS share information since we don't have the WASM library integrated
	fmt.Fprintf(outputBuilder, "DKLS Shares Information:\n")
	for i, share := range dklsShares {
		fmt.Fprintf(outputBuilder, "Share %d:\n", i+1)
		fmt.Fprintf(outputBuilder, "  Party ID: %s\n", share.PartyID)
		fmt.Fprintf(outputBuilder, "  Share ID: %s\n", share.ID)
		fmt.Fprintf(outputBuilder, "  Share Data: %x\n", share.ShareData[:min(len(share.ShareData), 64)]) // Show first 64 bytes
		fmt.Fprintf(outputBuilder, "  Share Data Length: %d bytes\n\n", len(share.ShareData))
	}

	fmt.Fprintf(outputBuilder, "\nNote: DKLS key reconstruction requires the DKLS WASM library.\n")
	fmt.Fprintf(outputBuilder, "Currently displaying share information only.\n")
	fmt.Fprintf(outputBuilder, "To complete DKLS key recovery, integrate the actual DKLS WASM library.\n")

	return nil
}