package derive

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dogec "github.com/eager7/dogd/btcec"
	dogechaincfg "github.com/eager7/dogd/chaincfg"
	"github.com/eager7/dogutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gcash/bchd/bchec"
	bchChainCfg "github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchutil"
	ltcchaincfg "github.com/ltcsuite/ltcd/chaincfg"
	"github.com/ltcsuite/ltcd/ltcutil"
	"golang.org/x/crypto/sha3"
)

func DeriveECDSACoins(rootPrivKeyBytes, rootChainCodeBytes []byte) ([]CoinKey, error) {
	privateKey := secp256k1.PrivKeyFromBytes(rootPrivKeyBytes)
	net := &chaincfg.MainNetParams
	extKey := hdkeychain.NewExtendedKey(
		net.HDPrivateKeyID[:],
		privateKey.Serialize(),
		rootChainCodeBytes,
		[]byte{0x00, 0x00, 0x00, 0x00},
		0, 0, true,
	)

	defs := getECDSACoinDefs()
	var results []CoinKey

	for _, def := range defs {
		derivedKey, err := derivePrivateKey(def.DerivePath, extKey)
		if err != nil {
			continue
		}

		privKey, err := derivedKey.ECPrivKey()
		if err != nil {
			continue
		}
		pubKey, err := derivedKey.ECPubKey()
		if err != nil {
			continue
		}

		coinKey, err := def.Derive(privKey.Serialize(), pubKey.SerializeCompressed())
		if err != nil {
			continue
		}
		coinKey.Name = def.Name
		coinKey.DerivePath = def.DerivePath
		results = append(results, coinKey)
	}

	return results, nil
}

func derivePrivateKey(derivePath string, rootKey *hdkeychain.ExtendedKey) (*hdkeychain.ExtendedKey, error) {
	pathBuf, err := getDerivePathBytes(derivePath)
	if err != nil {
		return nil, fmt.Errorf("get derive path bytes failed: %w", err)
	}
	key := rootKey
	for _, item := range pathBuf {
		key, err = key.Derive(item)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

func deriveBitcoin(privKey, pubKey []byte) (CoinKey, error) {
	net := &chaincfg.MainNetParams
	ecPrivKey := secp256k1.PrivKeyFromBytes(privKey)
	wif, err := btcutil.NewWIF(ecPrivKey, net, true)
	if err != nil {
		return CoinKey{}, err
	}
	addr, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pubKey), net)
	if err != nil {
		return CoinKey{}, err
	}
	return CoinKey{
		Address:       addr.EncodeAddress(),
		HexPrivateKey: hex.EncodeToString(privKey),
		HexPublicKey:  hex.EncodeToString(pubKey),
		WIFPrivateKey: wif.String(),
	}, nil
}

func deriveBitcoinCash(privKey, pubKey []byte) (CoinKey, error) {
	net := &bchChainCfg.MainNetParams
	bchPriv, _ := bchec.PrivKeyFromBytes(bchec.S256(), privKey)
	wif, err := bchutil.NewWIF(bchPriv, net, true)
	if err != nil {
		return CoinKey{}, err
	}
	addr, err := bchutil.NewAddressPubKeyHash(bchutil.Hash160(pubKey), net)
	if err != nil {
		return CoinKey{}, err
	}
	return CoinKey{
		Address:       addr.EncodeAddress(),
		HexPrivateKey: hex.EncodeToString(privKey),
		HexPublicKey:  hex.EncodeToString(pubKey),
		WIFPrivateKey: wif.String(),
	}, nil
}

func deriveDogecoin(privKey, pubKey []byte) (CoinKey, error) {
	net := &dogechaincfg.MainNetParams
	dogePriv, _ := dogec.PrivKeyFromBytes(dogec.S256(), privKey)
	wif, err := dogutil.NewWIF(dogePriv, net, true)
	if err != nil {
		return CoinKey{}, err
	}
	addr, err := dogutil.NewAddressPubKeyHash(dogutil.Hash160(pubKey), net)
	if err != nil {
		return CoinKey{}, err
	}
	return CoinKey{
		Address:       addr.EncodeAddress(),
		HexPrivateKey: hex.EncodeToString(privKey),
		HexPublicKey:  hex.EncodeToString(pubKey),
		WIFPrivateKey: wif.String(),
	}, nil
}

func deriveLitecoin(privKey, pubKey []byte) (CoinKey, error) {
	net := &ltcchaincfg.MainNetParams
	ecPrivKey := secp256k1.PrivKeyFromBytes(privKey)
	wif, err := ltcutil.NewWIF(ecPrivKey, net, true)
	if err != nil {
		return CoinKey{}, err
	}
	addr, err := ltcutil.NewAddressWitnessPubKeyHash(ltcutil.Hash160(pubKey), net)
	if err != nil {
		return CoinKey{}, err
	}
	return CoinKey{
		Address:       addr.EncodeAddress(),
		HexPrivateKey: hex.EncodeToString(privKey),
		HexPublicKey:  hex.EncodeToString(pubKey),
		WIFPrivateKey: wif.String(),
	}, nil
}

func deriveEthereum(privKey, pubKey []byte) (CoinKey, error) {
	ecPrivKey := secp256k1.PrivKeyFromBytes(privKey)
	ethAddr := crypto.PubkeyToAddress(*ecPrivKey.PubKey().ToECDSA()).Hex()
	return CoinKey{
		Address:       ethAddr,
		HexPrivateKey: hex.EncodeToString(privKey),
		HexPublicKey:  hex.EncodeToString(pubKey),
	}, nil
}

func deriveTron(privKey, pubKey []byte) (CoinKey, error) {
	ecPrivKey := secp256k1.PrivKeyFromBytes(privKey)
	pubKeyECDSA := ecPrivKey.PubKey().ToECDSA()
	pubKeyBytes := crypto.FromECDSAPub(pubKeyECDSA)
	pubKeyNoPrefix := pubKeyBytes[1:]

	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubKeyNoPrefix)
	pubKeyHash := hash.Sum(nil)
	ethAddr := pubKeyHash[12:]

	tronAddr := make([]byte, 21)
	tronAddr[0] = 0x41
	copy(tronAddr[1:], ethAddr)

	firstSHA := sha256.Sum256(tronAddr)
	secondSHA := sha256.Sum256(firstSHA[:])
	checksum := secondSHA[:4]

	addrWithChecksum := make([]byte, 25)
	copy(addrWithChecksum[:21], tronAddr)
	copy(addrWithChecksum[21:], checksum)

	return CoinKey{
		Address:       base58.Encode(addrWithChecksum),
		HexPrivateKey: hex.EncodeToString(privKey),
		HexPublicKey:  hex.EncodeToString(pubKeyBytes),
	}, nil
}

func cosmosDeriver(hrp, coinName string) func(privKey, pubKey []byte) (CoinKey, error) {
	return func(privKey, pubKey []byte) (CoinKey, error) {
		addr, err := cosmosAddress(pubKey, hrp)
		if err != nil {
			return CoinKey{}, err
		}
		return CoinKey{
			Address:       addr,
			HexPrivateKey: hex.EncodeToString(privKey),
			HexPublicKey:  hex.EncodeToString(pubKey),
		}, nil
	}
}
