
package dkls

import (
	"strings"
)

// AddressGenerator interface for cryptocurrency address generation
// This interface allows both native Go and WASM implementations
type AddressGenerator interface {
	GenerateBitcoinAddress(privateKeyHex string) (address string, wif string, err error)
	GenerateEthereumAddress(privateKeyHex string) (address string, err error)
	GenerateMultiCoinAddresses(privateKeyHex string) (map[string]AddressInfo, error)
	ValidatePrivateKey(privateKeyHex string) bool
}

// AddressInfo contains address information for a cryptocurrency
type AddressInfo struct {
	Address    string `json:"address"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey,omitempty"`
	WIF        string `json:"wif,omitempty"`
	DerivePath string `json:"derivePath,omitempty"`
}

// NativeAddressGenerator implements AddressGenerator using native Go libraries
type NativeAddressGenerator struct {
	processor *NativeDKLSProcessor
}

// NewNativeAddressGenerator creates a new native address generator
func NewNativeAddressGenerator() *NativeAddressGenerator {
	return &NativeAddressGenerator{
		processor: NewNativeDKLSProcessor(),
	}
}

// GenerateBitcoinAddress generates Bitcoin address from private key
func (g *NativeAddressGenerator) GenerateBitcoinAddress(privateKeyHex string) (string, string, error) {
	var output strings.Builder
	err := g.processor.generateDirectBitcoinAddress(mustHexDecode(privateKeyHex), &output)
	if err != nil {
		return "", "", err
	}
	
	// Parse the output to extract address and WIF
	// This is a simplified implementation - in practice you'd want proper parsing
	outputStr := output.String()
	lines := strings.Split(outputStr, "\n")
	
	var address, wif string
	for _, line := range lines {
		if strings.Contains(line, "Address (P2WPKH):") {
			address = strings.TrimSpace(strings.Split(line, ":")[1])
		}
		if strings.Contains(line, "WIF Private Key:") {
			wif = strings.TrimSpace(strings.Split(line, ":")[1])
		}
	}
	
	return address, wif, nil
}

// GenerateEthereumAddress generates Ethereum address from private key
func (g *NativeAddressGenerator) GenerateEthereumAddress(privateKeyHex string) (string, error) {
	var output strings.Builder
	err := g.processor.generateDirectEthereumAddress(mustHexDecode(privateKeyHex), &output)
	if err != nil {
		return "", err
	}
	
	// Parse the output to extract address
	outputStr := output.String()
	lines := strings.Split(outputStr, "\n")
	
	for _, line := range lines {
		if strings.Contains(line, "Address:") {
			return strings.TrimSpace(strings.Split(line, ":")[1]), nil
		}
	}
	
	return "", nil
}

// GenerateMultiCoinAddresses generates addresses for multiple cryptocurrencies
func (g *NativeAddressGenerator) GenerateMultiCoinAddresses(privateKeyHex string) (map[string]AddressInfo, error) {
	addresses := make(map[string]AddressInfo)
	
	// Bitcoin
	btcAddr, wif, err := g.GenerateBitcoinAddress(privateKeyHex)
	if err == nil {
		addresses["bitcoin"] = AddressInfo{
			Address:    btcAddr,
			WIF:        wif,
			PrivateKey: privateKeyHex,
		}
	}
	
	// Ethereum
	ethAddr, err := g.GenerateEthereumAddress(privateKeyHex)
	if err == nil {
		addresses["ethereum"] = AddressInfo{
			Address:    ethAddr,
			PrivateKey: privateKeyHex,
		}
	}
	
	return addresses, nil
}

// ValidatePrivateKey validates if a private key is valid for secp256k1
func (g *NativeAddressGenerator) ValidatePrivateKey(privateKeyHex string) bool {
	privateKeyBytes := mustHexDecode(privateKeyHex)
	return g.processor.isValidSecp256k1PrivateKey(privateKeyBytes)
}

// Helper function to decode hex (panics on error for internal use)
func mustHexDecode(hexStr string) []byte {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic("invalid hex string: " + hexStr)
	}
	return bytes
}

// Future WASM integration point
// WASMAddressGenerator would implement the same AddressGenerator interface
// but use the WASM vs_wasm library for address generation
type WASMAddressGenerator struct {
	// Future: integrate with vs_wasm for address generation
	// This would call JavaScript functions that use the WASM library
}

// GetAddressGenerator returns the appropriate address generator
// In the future, this could switch between native and WASM based on availability
func GetAddressGenerator() AddressGenerator {
	// For now, always return native generator
	// Future: detect WASM availability and return WASMAddressGenerator if available
	return NewNativeAddressGenerator()
}
