package keyprocessing

import (
	"fmt"
	"strings"
	"log"
	"os/exec"
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

	// Initialize DKLS wrapper
	dklsWrapper := dkls.NewDKLSWrapper()
	if err := dklsWrapper.Initialize(); err != nil {
		fmt.Fprintf(outputBuilder, "DKLS wrapper initialization failed: %v\n", err)
		fmt.Fprintf(outputBuilder, "Displaying share information only...\n\n")
	}

	// Display the DKLS share information
	fmt.Fprintf(outputBuilder, "DKLS Shares Information:\n")
	for i, share := range dklsShares {
		fmt.Fprintf(outputBuilder, "DKLS Share %d:\n", i+1)
		fmt.Fprintf(outputBuilder, "  Party ID: %s\n", share.PartyID)
		fmt.Fprintf(outputBuilder, "  Share ID: %s\n", share.ID)
		fmt.Fprintf(outputBuilder, "  Share Data Length: %d bytes\n", len(share.ShareData))
		if len(share.ShareData) > 0 {
			fmt.Fprintf(outputBuilder, "  Share Data Preview: %x...\n", share.ShareData[:min(len(share.ShareData), 32)])
		}
		fmt.Fprintf(outputBuilder, "\n")
	}

	// Try native Go DKLS reconstruction first
	fmt.Fprintf(outputBuilder, "Attempting native Go DKLS key reconstruction...\n")
	if err := dkls.ProcessDKLSSharesNative(dklsShares, partyIDs, threshold, outputBuilder); err != nil {
		fmt.Fprintf(outputBuilder, "Native reconstruction failed: %v\n", err)
		
		// Fallback to WASM if available
		if dklsWrapper != nil {
			fmt.Fprintf(outputBuilder, "\nFalling back to WASM reconstruction...\n")
			
			// Check if Node.js is available
			if _, err := exec.LookPath("node"); err != nil {
				fmt.Fprintf(outputBuilder, "Node.js not found. Please install Node.js to enable WASM DKLS reconstruction.\n")
			} else {
				response, err := dklsWrapper.ExportKey(dklsShares, partyIDs, threshold)
				if err != nil {
					fmt.Fprintf(outputBuilder, "WASM reconstruction failed: %v\n", err)
				} else if response.Success {
					fmt.Fprintf(outputBuilder, "\n=== WASM DKLS Key Reconstruction Successful! ===\n")
					fmt.Fprintf(outputBuilder, "Private Key: %s\n", response.PrivateKey)
					fmt.Fprintf(outputBuilder, "Public Key: %s\n", response.PublicKey)
				} else {
					fmt.Fprintf(outputBuilder, "WASM reconstruction failed: %s\n", response.Error)
				}
			}
		}
	}

	return nil
}