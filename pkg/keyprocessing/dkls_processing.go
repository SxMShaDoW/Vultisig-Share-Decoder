package keyprocessing

import (
	"fmt"
	"strings"
	"os/exec"
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
		fmt.Fprintf(outputBuilder, "1. Replace static/vs_wasm.js with the actual file from GitHub\n")
		fmt.Fprintf(outputBuilder, "2. Ensure vs_wasm_bg.wasm is in the static/ directory\n")
		fmt.Fprintf(outputBuilder, "3. Ensure Node.js is installed for WASM execution\n")
		fmt.Fprintf(outputBuilder, "\nCurrently displaying share information only.\n")
		return nil
	}

	// Attempt actual key reconstruction
	fmt.Fprintf(outputBuilder, "WASM Library Status: Available\n")
	
	// Check if Node.js is available
	if _, err := exec.LookPath("node"); err != nil {
		fmt.Fprintf(outputBuilder, "Node.js not found. Please install Node.js to enable DKLS reconstruction.\n")
		return nil
	}
	
	response, err := dklsWrapper.ExportKey(dklsShares, partyIDs, threshold)
	if err != nil {
		fmt.Fprintf(outputBuilder, "Key reconstruction failed: %v\n", err)
		fmt.Fprintf(outputBuilder, "\nThis may be due to:\n")
		fmt.Fprintf(outputBuilder, "- WASM library not properly loaded\n")
		fmt.Fprintf(outputBuilder, "- Incompatible share format\n")
		fmt.Fprintf(outputBuilder, "- Missing Node.js dependencies\n")
		return nil
	}

	if response.Success {
		fmt.Fprintf(outputBuilder, "\n=== DKLS Key Reconstruction Successful! ===\n")
		fmt.Fprintf(outputBuilder, "Private Key: %s\n", response.PrivateKey)
		fmt.Fprintf(outputBuilder, "Public Key: %s\n", response.PublicKey)
		
		// TODO: Add cryptocurrency-specific key derivation here
		fmt.Fprintf(outputBuilder, "\nNote: Cryptocurrency-specific derivation not yet implemented for DKLS.\n")
	} else {
		fmt.Fprintf(outputBuilder, "Key reconstruction failed: %s\n", response.Error)
	}

	return nil
}
package keyprocessing

import (
	"fmt"
	"strings"
	"log"
	"os/exec"
	"main/pkg/dkls"
)

// ProcessDKLSKeys processes DKLS key shares to reconstruct private keys
func ProcessDKLSKeys(threshold int, dklsShares []dkls.DKLSShareData, partyIDs []string, outputBuilder *strings.Builder) error {
	log.Printf("Processing DKLS keys with threshold: %d, number of shares: %d", threshold, len(dklsShares))

	// Validate input parameters
	if threshold <= 0 {
		return fmt.Errorf("invalid threshold: %d", threshold)
	}
	if len(dklsShares) == 0 {
		return fmt.Errorf("no DKLS shares provided")
	}
	if threshold > len(dklsShares) {
		return fmt.Errorf("threshold (%d) cannot be greater than number of shares (%d)", threshold, len(dklsShares))
	}

	fmt.Fprintf(outputBuilder, "=== DKLS Key Reconstruction ===\n")
	fmt.Fprintf(outputBuilder, "Using %d out of %d shares for reconstruction\n\n", threshold, len(dklsShares))

	// For now, just display the share information since actual DKLS reconstruction
	// would require the mobile-tss-lib DKLS implementation
	for i, share := range dklsShares {
		fmt.Fprintf(outputBuilder, "DKLS Share %d:\n", i+1)
		fmt.Fprintf(outputBuilder, "  Party ID: %s\n", share.PartyID)
		fmt.Fprintf(outputBuilder, "  Share ID: %s\n", share.ID)
		fmt.Fprintf(outputBuilder, "  Share Data Length: %d bytes\n", len(share.ShareData))
		fmt.Fprintf(outputBuilder, "\n")
	}

	fmt.Fprintf(outputBuilder, "Note: DKLS key reconstruction requires the full mobile-tss-lib implementation.\n")
	fmt.Fprintf(outputBuilder, "This tool currently displays share information for DKLS vaults.\n")
	fmt.Fprintf(outputBuilder, "For actual key reconstruction, please use the official Vultisig mobile app.\n")

	return nil
}
