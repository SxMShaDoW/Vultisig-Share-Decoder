package keyhandlers

import (
	"encoding/hex"
	"fmt"
	"strings"
	"crypto/ed25519"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	coskey "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gcash/bchd/bchec"
	bchChainCfg "github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchutil"
	dogec "github.com/eager7/dogd/btcec"
	dogechaincfg "github.com/eager7/dogd/chaincfg"
	"github.com/eager7/dogutil"
	"github.com/ltcsuite/ltcd/ltcutil"
	ltcchaincfg "github.com/ltcsuite/ltcd/chaincfg"
	"main/tss"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	"crypto/sha256"
	"github.com/tonkeeper/tongo/wallet"
)

func GetDerivedPrivateKeys(derivePath string, rootPrivateKey *hdkeychain.ExtendedKey) (*hdkeychain.ExtendedKey, error) {
	pathBuf, err := tss.GetDerivePathBytes(derivePath)
	if err != nil {
		return nil, fmt.Errorf("get derive path bytes failed: %w", err)
	}
	key := rootPrivateKey
	for _, item := range pathBuf {
		key, err = key.Derive(item)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

func ShowEthereumKey(extendedPrivateKey *hdkeychain.ExtendedKey, outputBuilder *strings.Builder) error {
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}

	fmt.Fprintf(outputBuilder, "\nhex encoded non-hardened public key for ethereum:%s\n", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	fmt.Fprintf(outputBuilder, "\nhex encoded private key for ethereum:%s\n", hex.EncodeToString(nonHardenedPrivKey.Serialize()))
	fmt.Fprintf(outputBuilder, "\nethereum address:%s\n", crypto.PubkeyToAddress(*nonHardenedPubKey.ToECDSA()).Hex())
	return nil
}

func ShowBitcoinKey(extendedPrivateKey *hdkeychain.ExtendedKey, outputBuilder *strings.Builder) error {
	net := &chaincfg.MainNetParams
	fmt.Fprintf(outputBuilder, "\nnon-hardened extended private key for bitcoin:%s\n", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}
	wif, err := btcutil.NewWIF(nonHardenedPrivKey, net, true)
	if err != nil {
		return err
	}

	addressPubKey, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(nonHardenedPubKey.SerializeCompressed()), net)
	if err != nil {
		return err
	}
	fmt.Fprintf(outputBuilder, "\nhex encoded non-hardened public key for bitcoin:%s\n", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	fmt.Fprintf(outputBuilder, "\naddress:%s\n", addressPubKey.EncodeAddress())
	fmt.Fprintf(outputBuilder, "\nWIF private key for bitcoin: p2wpkh:%s\n", wif.String())
	return nil
}

func ShowBitcoinCashKey(extendedPrivateKey *hdkeychain.ExtendedKey, outputBuilder *strings.Builder) error {
	net := &bchChainCfg.MainNetParams
	fmt.Fprintf(outputBuilder, "\nnon-hardened extended private key for bitcoinCash:%s\n", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}
	bchNonHardenedPrivKey, _ := bchec.PrivKeyFromBytes(bchec.S256(), nonHardenedPrivKey.Serialize())
	wif, err := bchutil.NewWIF(bchNonHardenedPrivKey, net, true)
	if err != nil {
		return err
	}

	addressPubKey, err := bchutil.NewAddressPubKeyHash(bchutil.Hash160(nonHardenedPubKey.SerializeCompressed()), net)
	if err != nil {
		return err
	}
	fmt.Fprintf(outputBuilder, "\nhex encoded non-hardened public key for bitcoinCash:%s", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	fmt.Fprintf(outputBuilder, "\naddress:%s\n", addressPubKey.EncodeAddress())
	fmt.Fprintf(outputBuilder, "\nWIF private key for bitcoinCash: %s\n", wif.String())
	return nil
}

func ShowDogecoinKey(extendedPrivateKey *hdkeychain.ExtendedKey, outputBuilder *strings.Builder) error {
	net := &dogechaincfg.MainNetParams
	fmt.Fprintf(outputBuilder, "\nnon-hardened extended private key for dogecoin:%s\n", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}
	dogutilNonHardenedPrivKey, _ := dogec.PrivKeyFromBytes(dogec.S256(), nonHardenedPrivKey.Serialize())
	wif, err := dogutil.NewWIF(dogutilNonHardenedPrivKey, net, true)
	if err != nil {
		return err
	}

	addressPubKey, err := dogutil.NewAddressPubKeyHash(dogutil.Hash160(nonHardenedPubKey.SerializeCompressed()), net)
	if err != nil {
		return err
	}
	fmt.Fprintf(outputBuilder, "\nhex encoded non-hardened public key for dogecoin:%s\n", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	fmt.Fprintf(outputBuilder, "\naddress:%s\n", addressPubKey.EncodeAddress())
	fmt.Fprintf(outputBuilder, "\nWIF private key for dogecoin: %s\n", wif.String())
	return nil
}

func ShowLitecoinKey(extendedPrivateKey *hdkeychain.ExtendedKey, outputBuilder *strings.Builder) error {
	net := &ltcchaincfg.MainNetParams
	fmt.Fprintf(outputBuilder, "\nnon-hardened extended private key for litcoin:%s", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}
	wif, err := ltcutil.NewWIF(nonHardenedPrivKey, net, true)
	if err != nil {
		return err
	}

	addressPubKey, err := ltcutil.NewAddressWitnessPubKeyHash(ltcutil.Hash160(nonHardenedPubKey.SerializeCompressed()), net)
	if err != nil {
		return err
	}
	fmt.Fprintf(outputBuilder, "\nhex encoded non-hardened public key for litecoin:%s\n", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	fmt.Fprintf(outputBuilder, "\naddress:%s\n", addressPubKey.EncodeAddress())
	fmt.Fprintf(outputBuilder, "\nWIF private key for litecoin: %s\n", wif.String())
	return nil
}

func CosmosLikeKeyHandler(extendedPrivateKey *hdkeychain.ExtendedKey, bech32PrefixAcc string, bech32PrefixVal string, bech32PrefixNode string, outputBuilder *strings.Builder, coinName string) error {
	fmt.Fprintf(outputBuilder, "\nnon-hardened extended private key for %s:%s\n", coinName, extendedPrivateKey.String())

	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}

	fmt.Fprintf(outputBuilder, "\nhex encoded non-hardened private key for %s:%s\n", coinName, hex.EncodeToString(nonHardenedPrivKey.Serialize()))
	fmt.Fprintf(outputBuilder, "\nhex encoded non-hardened public key for %s:%s\n", coinName, hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))

	compressedPubkey := coskey.PubKey{
		Key: nonHardenedPubKey.SerializeCompressed(),
	}

	// Generate the address bytes
	addrBytes := types.AccAddress(compressedPubkey.Address().Bytes())

	// Use sdk.Bech32ifyAccPub with the correct prefix
	bech32Addr := sdk.MustBech32ifyAddressBytes(bech32PrefixAcc, addrBytes)

	fmt.Fprintf(outputBuilder, "\naddress:%s\n", bech32Addr)
	return nil
}

func ShowThorchainKey(extendedPrivateKey *hdkeychain.ExtendedKey, outputBuilder *strings.Builder) error {

	fmt.Fprintf(outputBuilder, "\nnon-hardened extended private key for THORChain:%s\n", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}

	fmt.Fprintf(outputBuilder, "\nhex encoded non-hardened private key for THORChain:%s\n", hex.EncodeToString(nonHardenedPrivKey.Serialize()))
	fmt.Fprintf(outputBuilder, "\nhex encoded non-hardened public key for THORChain:%s\n", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("thor", "thorpub")
	config.SetBech32PrefixForValidator("thorv", "thorvpub")
	config.SetBech32PrefixForConsensusNode("thorc", "thorcpub")

	compressedPubkey := coskey.PubKey{
		Key: nonHardenedPubKey.SerializeCompressed(),
	}
	addr := types.AccAddress(compressedPubkey.Address().Bytes())
	fmt.Fprintf(outputBuilder, "address:%s", addr.String())
	return nil
}

func ShowMayachainKey(extendedPrivateKey *hdkeychain.ExtendedKey, outputBuilder *strings.Builder) error {
	fmt.Fprintf(outputBuilder, "\nnon-hardened extended private key for MAYAChain:%s\n", extendedPrivateKey.String())
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}

	fmt.Fprintf(outputBuilder, "\nhex encoded non-hardened private key for MAYAChain:%s\n", hex.EncodeToString(nonHardenedPrivKey.Serialize()))
	fmt.Fprintf(outputBuilder, "\nhex encoded non-hardened public key for MAYAChain:%s\n", hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("maya", "mayapub")
	config.SetBech32PrefixForValidator("mayav", "mayavpub")
	config.SetBech32PrefixForConsensusNode("mayac", "mayacpub")

	compressedPubkey := coskey.PubKey{
		Key: nonHardenedPubKey.SerializeCompressed(),
	}
	addr := types.AccAddress(compressedPubkey.Address().Bytes())
	fmt.Fprintf(outputBuilder, "\naddress:%s\n", addr.String())
	return nil
}

// ProcessRootKeyForCoins processes root key material through the coin handlers
func ProcessRootKeyForCoins(rootPrivateKeyBytes []byte, rootChainCodeBytes []byte, coinConfigs []CoinConfig, outputBuilder *strings.Builder) error {
	// Create secp256k1 private key from bytes
	privateKey := secp256k1.PrivKeyFromBytes(rootPrivateKeyBytes)
	publicKey := privateKey.PubKey()

	// Display root key information
	hexPubKey := hex.EncodeToString(publicKey.SerializeCompressed())
	fmt.Fprintf(outputBuilder, "\nhex encoded root pubkey(ECDSA): %s\n", hexPubKey)
	fmt.Fprintf(outputBuilder, "\nhex encoded root privkey(ECDSA): %s\n", hex.EncodeToString(privateKey.Serialize()))

	// Create extended key for derivation
	net := &chaincfg.MainNetParams
	fmt.Fprintf(outputBuilder, "\nchaincode: %s\n", hex.EncodeToString(rootChainCodeBytes))

	extendedPrivateKey := hdkeychain.NewExtendedKey(
		net.HDPrivateKeyID[:],
		privateKey.Serialize(),
		rootChainCodeBytes,
		[]byte{0x00, 0x00, 0x00, 0x00},
		0,
		0,
		true,
	)
	fmt.Fprintf(outputBuilder, "\nextended private key full: %s\n", extendedPrivateKey.String())

	// Process each coin configuration
	for _, coin := range coinConfigs {
		fmt.Fprintf(outputBuilder, "\nRecovering %s key....\n", coin.Name)

		key, err := GetDerivedPrivateKeys(coin.DerivePath, extendedPrivateKey)
		if err != nil {
			return fmt.Errorf("error deriving private key for %s: %w", coin.Name, err)
		}

		fmt.Fprintf(outputBuilder, "\nprivate key for %s: %s \n", coin.Name, key.String())

		if err := coin.Action(key, outputBuilder); err != nil {
			fmt.Printf("error showing keys for %s: %v\n", coin.Name, err)
		}
	}

	return nil
}

// ProcessEdDSAKeyForCoins processes EdDSA key material for EdDSA-based coins
func ProcessEdDSAKeyForCoins(eddsaPrivateKeyBytes []byte, eddsaPublicKeyBytes []byte, coinConfigs []CoinConfigEdDSA, outputBuilder *strings.Builder) error {
	// The EdDSA keys passed here are the actual reconstructed EdDSA root keys

	// Process each EdDSA coin configuration
	for _, coin := range coinConfigs {
		fmt.Fprintf(outputBuilder, "\nRecovering %s key....\n", coin.Name)

		// Call the coin-specific action function
		if err := coin.Action(eddsaPrivateKeyBytes, eddsaPublicKeyBytes, outputBuilder); err != nil {
			return fmt.Errorf("error showing keys for %s: %w", coin.Name, err)
		}
	}

	return nil
}

// ShowSolanaKeyFromEdDSA shows Solana key information from raw Ed25519 keys
func ShowSolanaKeyFromEdDSA(eddsaPrivateKeyBytes []byte, eddsaPublicKeyBytes []byte, outputBuilder *strings.Builder) error {
	// For Solana, the Ed25519 public key IS the address
	solanaAddress := base58.Encode(eddsaPublicKeyBytes)

	fmt.Fprintf(outputBuilder, "\nhex encoded Ed25519 private key for solana:%s\n (Note: This is a private key scalar and can only be used for signing, not importing into another wallet)", hex.EncodeToString(eddsaPrivateKeyBytes))
	fmt.Fprintf(outputBuilder, "\nhex encoded Ed25519 public key for solana:%s\n", hex.EncodeToString(eddsaPublicKeyBytes))
	fmt.Fprintf(outputBuilder, "\nsolana address:%s\n", solanaAddress)

	return nil
}

// ShowSuiKeyFromEdDSA shows Sui key information from raw Ed25519 keys
func ShowSuiKeyFromEdDSA(eddsaPrivateKeyBytes []byte, eddsaPublicKeyBytes []byte, outputBuilder *strings.Builder) error {
	// For Sui, we need to create an address from the public key using Blake2b hashing
	// Sui address = Blake2b(scheme_flag || public_key)[0:20]
	// where scheme_flag = 0x00 for Ed25519
	
	// Create the input for hashing: scheme flag (0x00 for Ed25519) + public key
	input := make([]byte, 1+len(eddsaPublicKeyBytes))
	input[0] = 0x00 // Ed25519 scheme flag
	copy(input[1:], eddsaPublicKeyBytes)
	
	// Hash using Blake2b
	hash := blake2b.Sum256(input)


	// Use full hash for address
	addressBytes := hash[:]
	
	// Convert to hex with 0x prefix for Sui address format
	suiAddress := "0x" + hex.EncodeToString(addressBytes)

	fmt.Fprintf(outputBuilder, "\nhex encoded Ed25519 private key for sui:%s (Note: This is a private key scalar and can only be used for signing, not importing into another wallet)\n", hex.EncodeToString(eddsaPrivateKeyBytes))
	fmt.Fprintf(outputBuilder, "\nhex encoded Ed25519 public key for sui:%s\n", hex.EncodeToString(eddsaPublicKeyBytes))
	fmt.Fprintf(outputBuilder, "\nsui address:%s\n", suiAddress)

	return nil
}

// ShowTronKey shows Tron key information from ECDSA keys
func ShowTronKey(extendedPrivateKey *hdkeychain.ExtendedKey, outputBuilder *strings.Builder) error {
	nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
	if err != nil {
		return err
	}
	nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
	if err != nil {
		return err
	}

	// Get uncompressed public key (64 bytes + 0x04 prefix)
	pubKeyECDSA := nonHardenedPubKey.ToECDSA()
	pubKeyBytes := crypto.FromECDSAPub(pubKeyECDSA)
	
	// Remove the 0x04 prefix to get the 64-byte uncompressed key
	pubKeyNoPrefix := pubKeyBytes[1:]
	
	// Hash with Keccak256
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubKeyNoPrefix)
	pubKeyHash := hash.Sum(nil)
	
	// Take the last 20 bytes
	ethAddr := pubKeyHash[12:]
	
	// Prefix with Tron version byte (0x41 for mainnet)
	tronAddr := make([]byte, 21)
	tronAddr[0] = 0x41
	copy(tronAddr[1:], ethAddr)
	
	// Calculate checksum using double SHA256
	firstSHA := sha256.Sum256(tronAddr)
	secondSHA := sha256.Sum256(firstSHA[:])
	checksum := secondSHA[:4]
	
	// Combine address + checksum and encode with Base58
	addrWithChecksum := make([]byte, 25)
	copy(addrWithChecksum[:21], tronAddr)
	copy(addrWithChecksum[21:], checksum)
	
	tronAddress := base58.Encode(addrWithChecksum)

	fmt.Fprintf(outputBuilder, "\nhex encoded private key for tron:%s\n", hex.EncodeToString(nonHardenedPrivKey.Serialize()))
	fmt.Fprintf(outputBuilder, "\nhex encoded public key for tron:%s\n", hex.EncodeToString(pubKeyBytes))
	fmt.Fprintf(outputBuilder, "\ntron address:%s\n", tronAddress)

	return nil
}

// ShowTonKeyFromEdDSA shows TON key information from raw Ed25519 keys
func ShowTonKeyFromEdDSA(eddsaPrivateKeyBytes []byte, eddsaPublicKeyBytes []byte, outputBuilder *strings.Builder) error {
	// Validate key lengths
	if len(eddsaPrivateKeyBytes) != 32 {
		return fmt.Errorf("private key must be 32 bytes, got %d", len(eddsaPrivateKeyBytes))
	}
	if len(eddsaPublicKeyBytes) != 32 {
		return fmt.Errorf("public key must be 32 bytes, got %d", len(eddsaPublicKeyBytes))
	}

	// Set wallet parameters for mainnet V3R2 wallet
	ver := wallet.V4R2
	workchain := 0                         // Mainnet workchain
	networkGlobalID := int32(-239)         // Mainnet global ID
	subWalletId := uint32(698983191)       // Default subWalletId for v3R2

	// Generate address using the improved offline method
	addr, err := wallet.GenerateWalletAddress(
		ed25519.PublicKey(eddsaPublicKeyBytes),
		ver,
		&networkGlobalID,
		workchain,
		&subWalletId,
	)
	if err != nil {
		return fmt.Errorf("error generating wallet address: %w", err)
	}

	// Convert to user-friendly, non-bounceable, mainnet format
	tonAddress := addr.ToHuman(false, false) // bounceable=false, testnet=false

	fmt.Fprintf(outputBuilder, "\nhex encoded Ed25519 private key for ton:%s (Note: This is a private key scalar and can only be used for signing, not importing into another wallet)\n", hex.EncodeToString(eddsaPrivateKeyBytes))
	fmt.Fprintf(outputBuilder, "\nhex encoded Ed25519 public key for ton:%s\n", hex.EncodeToString(eddsaPublicKeyBytes))
	fmt.Fprintf(outputBuilder, "\nton address:%s\n", tonAddress)

	return nil
}

// GetEdDSACoins returns coins that use EdDSA
func GetEdDSACoins() []CoinConfigEdDSA {
	return []CoinConfigEdDSA{
		{
			Name:       "solana",
			DerivePath: "m/44'/501'/0'/0'",
			Action:     ShowSolanaKeyFromEdDSA,
		},
		{
			Name:       "sui",
			DerivePath: "m/44'/784'/0'/0'/0'",
			Action:     ShowSuiKeyFromEdDSA,
		},
		{
			Name:       "ton",
			DerivePath: "m/44'/607'/0'/0'/0'",
			Action:     ShowTonKeyFromEdDSA,
		},
	}
}