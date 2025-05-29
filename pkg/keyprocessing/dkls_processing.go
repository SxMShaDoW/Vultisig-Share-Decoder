package keyprocessing

import (
	"fmt"
	"strings"
	"log"
	"main/pkg/dkls"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

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

	// Try native Go DKLS reconstruction first using WASM-pattern approach
	fmt.Fprintf(outputBuilder, "Attempting native Go DKLS key reconstruction (WASM-pattern)...\n")
	if err := dkls.ProcessDKLSSharesNative(dklsShares, partyIDs, threshold, outputBuilder); err != nil {
		fmt.Fprintf(outputBuilder, "Native WASM-pattern reconstruction failed: %v\n", err)
	}

	return nil
}