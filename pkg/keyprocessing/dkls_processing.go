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

	// Try to initialize the WASM library for actual key reconstruction
	fmt.Fprintf(outputBuilder, "\nAttempting DKLS key reconstruction...\n")
	
	// Check if we have the WASM library available
	if err := dklsWrapper.Initialize(); err != nil {
		fmt.Fprintf(outputBuilder, "\nWASM Library Status: Not available (%v)\n", err)
		fmt.Fprintf(outputBuilder, "\nTo enable full DKLS key reconstruction:\n")
		fmt.Fprintf(outputBuilder, "1. Download vs_wasm_bg.wasm from: https://github.com/vultisig/vultisig-windows/blob/main/lib/dkls/vs_wasm_bg.wasm\n")
		fmt.Fprintf(outputBuilder, "2. Place it in the static/ directory\n")
		fmt.Fprintf(outputBuilder, "3. Ensure Node.js is installed for WASM execution\n")
		fmt.Fprintf(outputBuilder, "\nCurrently displaying share information only.\n")
		return nil
	}

	// Attempt actual key reconstruction
	fmt.Fprintf(outputBuilder, "WASM Library Status: Available\n")
	response, err := dklsWrapper.ExportKey(dklsShares, partyIDs, threshold)
	if err != nil {
		fmt.Fprintf(outputBuilder, "Key reconstruction failed: %v\n", err)
		return nil
	}

	if response.Success {
		fmt.Fprintf(outputBuilder, "\n=== DKLS Key Reconstruction Successful! ===\n")
		fmt.Fprintf(outputBuilder, "Private Key: %x\n", response.PrivateKey)
		fmt.Fprintf(outputBuilder, "Public Key: %x\n", response.PublicKey)
	} else {
		fmt.Fprintf(outputBuilder, "Key reconstruction failed: %s\n", response.Error)
	}

	return nil
}