package dkls

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"main/pkg/types"
	"os"
	"os/exec"
)

// DKLSWrapper provides a Go interface to the DKLS WASM library
type DKLSWrapper struct {
	initialized bool
	wasmPath    string
	jsPath      string
}

// NewDKLSWrapper creates a new instance of the DKLS wrapper
func NewDKLSWrapper() *DKLSWrapper {
	return &DKLSWrapper{
		initialized: false,
		wasmPath:    "static/vs_wasm_bg.wasm",
		jsPath:      "static/vs_wasm.js",
	}
}

// Initialize initializes the DKLS WASM library
func (w *DKLSWrapper) Initialize() error {
	// Check if WASM files exist
	if _, err := os.Stat(w.wasmPath); os.IsNotExist(err) {
		return fmt.Errorf("DKLS WASM binary not found at %s", w.wasmPath)
	}
	if _, err := os.Stat(w.jsPath); os.IsNotExist(err) {
		return fmt.Errorf("DKLS JS wrapper not found at %s", w.jsPath)
	}

	w.initialized = true
	log.Println("DKLS wrapper initialized with WASM library")
	return nil
}

// KeyExportRequest represents the structure for WASM key export
type KeyExportRequest struct {
	Shares    []WASMShareData `json:"shares"`
	PartyIDs  []string        `json:"partyIds"`
	Threshold int             `json:"threshold"`
}

// WASMShareData represents a share in the format expected by the WASM library
type WASMShareData struct {
	ID        string `json:"id"`
	ShareData string `json:"shareData"` // hex encoded
	PartyID   string `json:"partyId"`
}

// ExportKey reconstructs a private key from DKLS shares using the WASM library
func (w *DKLSWrapper) ExportKey(shares []DKLSShareData, partyIDs []string, threshold int) (*KeyExportResponse, error) {
	if !w.initialized {
		return nil, fmt.Errorf("DKLS wrapper not initialized")
	}

	if len(shares) < threshold {
		return nil, fmt.Errorf("insufficient shares: need %d, got %d", threshold, len(shares))
	}

	log.Printf("ExportKey: Processing %d shares with threshold %d", len(shares), threshold)

	// Convert shares to WASM format - use the raw keyshare bytes
	wasmShares := make([]WASMShareData, len(shares))
	for i, share := range shares {
		// Log keyshare data for debugging
		log.Printf("ExportKey: Share %d - ID: %s, PartyID: %s, Data length: %d", 
			i, share.ID, share.PartyID, len(share.ShareData))
		
		wasmShares[i] = WASMShareData{
			ID:        share.ID,
			ShareData: hex.EncodeToString(share.ShareData), // Convert to hex for WASM
			PartyID:   share.PartyID,
		}
	}

	request := KeyExportRequest{
		Shares:    wasmShares,
		PartyIDs:  partyIDs,
		Threshold: threshold,
	}

	// Create a temporary script to call the WASM library
	script := w.generateNodeScript(request)

	// Execute the script using Node.js
	result, err := w.executeNodeScript(script)
	if err != nil {
		return nil, fmt.Errorf("failed to execute DKLS key export: %w", err)
	}

	response := &KeyExportResponse{
		PrivateKey: result.PrivateKey,
		PublicKey:  result.PublicKey,
		Success:    result.Success,
		Error:      result.Error,
	}

	return response, nil
}

// NodeScriptResult represents the result from the Node.js script
type NodeScriptResult struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	Success    bool   `json:"success"`
	Error      string `json:"error"`
}

// generateNodeScript creates a Node.js script to call the WASM library
func (w *DKLSWrapper) generateNodeScript(request KeyExportRequest) string {
	requestJSON, _ := json.Marshal(request)

	script := fmt.Sprintf(`
const fs = require('fs');
const path = require('path');

// Load the WASM module
async function runDKLS() {
    try {
        // Import the WASM wrapper using CommonJS
        const wasmModule = require(path.resolve('%s'));
        const init = wasmModule.default || wasmModule;
        const { KeyExportSession, Keyshare } = wasmModule;

        // Initialize WASM with the binary file
        await init(fs.readFileSync(path.resolve('%s')));

        const request = %s;
        console.error('Processing', request.shares.length, 'shares with threshold', request.threshold);

        // Convert shares to the format expected by WASM
        let reconstructedKey = null;
        let publicKey = null;

        if (request.shares && request.shares.length >= request.threshold) {
            try {
                // Process each share to extract public key info
                for (let i = 0; i < request.shares.length; i++) {
                    const share = request.shares[i];
                    console.error('Share', i, '- ID:', share.id, 'PartyID:', share.partyId, 'Data length:', share.shareData.length);
                    
                    try {
                        // Try to create keyshare from raw data
                        const keyshareBytes = Buffer.from(share.shareData, 'hex');
                        const keyshare = Keyshare.fromBytes(keyshareBytes);
                        
                        // Extract public key
                        const pubKeyBytes = keyshare.publicKey();
                        const pubKey = Array.from(pubKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                        console.error('Share', i, 'public key:', pubKey);
                        
                        if (!publicKey) {
                            publicKey = pubKey;
                        }
                        
                        // Try key export with this share
                        if (i === 0) {
                            try {
                                const session = KeyExportSession.new(share.shareData, request.partyIds.join(','));
                                const privateKeyBytes = session.finish();
                                reconstructedKey = Array.from(privateKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
                                console.error('Successfully reconstructed private key from share', i);
                            } catch (exportError) {
                                console.error('Key export failed for share', i, ':', exportError.message);
                            }
                        }
                        
                    } catch (shareError) {
                        console.error('Failed to process share', i, ':', shareError.message);
                    }
                }

                if (reconstructedKey) {
                    console.log(JSON.stringify({
                        privateKey: reconstructedKey,
                        publicKey: publicKey || "unavailable",
                        success: true,
                        error: ""
                    }));
                } else {
                    console.log(JSON.stringify({
                        privateKey: "",
                        publicKey: publicKey || "unavailable",
                        success: false,
                        error: "Could not reconstruct private key from any share"
                    }));
                }

            } catch (reconstructError) {
                console.log(JSON.stringify({
                    privateKey: "",
                    publicKey: "",
                    success: false,
                    error: "DKLS reconstruction failed: " + reconstructError.message
                }));
            }
        } else {
            console.log(JSON.stringify({
                privateKey: "",
                publicKey: "",
                success: false,
                error: "Insufficient shares for reconstruction"
            }));
        }

    } catch (error) {
        console.log(JSON.stringify({
            privateKey: "",
            publicKey: "",
            success: false,
            error: "WASM initialization failed: " + error.message
        }));
    }
}

runDKLS().catch(console.error);
`, w.jsPath, w.wasmPath, string(requestJSON))

	return script
}

// executeNodeScript executes a Node.js script and returns the result
func (w *DKLSWrapper) executeNodeScript(script string) (*NodeScriptResult, error) {
	// Create temporary script file
	tmpFile, err := os.CreateTemp("", "dkls_script_*.js")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(script); err != nil {
		return nil, err
	}
	tmpFile.Close()

	// Execute with Node.js
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "node", tmpFile.Name())
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("node execution failed: %w", err)
	}

	var result NodeScriptResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse node output: %w", err)
	}

	return &result, nil
}

// ValidateShares validates that the provided shares are valid for DKLS
func (w *DKLSWrapper) ValidateShares(shares []DKLSShareData) error {
	if len(shares) == 0 {
		return fmt.Errorf("no shares provided")
	}

	for i, share := range shares {
		if share.ID == "" {
			return fmt.Errorf("share %d has empty ID", i)
		}
		if len(share.ShareData) == 0 {
			return fmt.Errorf("share %d has empty share data", i)
		}
		if share.PartyID == "" {
			return fmt.Errorf("share %d has empty party ID", i)
		}
	}

	return nil
}

// ConvertToDKLSLocalState converts DKLS shares to local state format
func (w *DKLSWrapper) ConvertToDKLSLocalState(shares []DKLSShareData, threshold int) (*types.DKLSLocalState, error) {
	if err := w.ValidateShares(shares); err != nil {
		return nil, err
	}

	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares to convert")
	}

	// Use the first share as the primary share
	primaryShare := shares[0]

	partyIDs := make([]string, len(shares))
	for i, share := range shares {
		partyIDs[i] = share.PartyID
	}

	dklsShare := types.DKLSShare{
		ID:        primaryShare.ID,
		ShareData: primaryShare.ShareData,
		Threshold: threshold,
		PartyID:   primaryShare.PartyID,
	}

	return &types.DKLSLocalState{
		Share:      dklsShare,
		PubKey:     hex.EncodeToString([]byte("placeholder_pubkey")),
		PartyIDs:   partyIDs,
		Threshold:  threshold,
		SchemeType: types.DKLS,
	}, nil
}

// ReconstructPrivateKey reconstructs the full private key from shares
func (w *DKLSWrapper) ReconstructPrivateKey(localState *types.DKLSLocalState) (*DKLSKeyResult, error) {
	if localState == nil {
		return nil, fmt.Errorf("nil local state provided")
	}

	// For actual implementation, this would use the WASM library
	result := &DKLSKeyResult{
		PrivateKeyHex: hex.EncodeToString(localState.Share.ShareData),
		PublicKeyHex:  localState.PubKey,
		Address:       "placeholder_address",
		KeyType:       types.ECDSA, // DKLS typically uses ECDSA
	}

	return result, nil
}

