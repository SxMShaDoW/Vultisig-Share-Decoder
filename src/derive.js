import { HDKey } from "@scure/bip32";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { bech32, base58, base58check, hex as hexCodec } from "@scure/base";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function bytesToHex(bytes) {
  return hexCodec.encode(bytes);
}

function hexToBytes(h) {
  return hexCodec.decode(h);
}

function hash160(data) {
  return ripemd160(sha256(data));
}

const b58check = base58check(sha256);

function wifEncode(privKey, versionByte) {
  const buf = new Uint8Array(34);
  buf[0] = versionByte;
  buf.set(privKey, 1);
  buf[33] = 0x01; // compressed flag
  return b58check.encode(buf);
}

function parsePath(derivePath) {
  return derivePath
    .split("/")
    .filter((s) => s && s !== "m")
    .map((s) => parseInt(s.replace("'", ""), 10));
}

function deriveChildKey(rootPrivKey, rootChainCode, path) {
  const hd = new HDKey({
    privateKey: rootPrivKey,
    chainCode: rootChainCode,
  });
  let key = hd;
  for (const index of parsePath(path)) {
    key = key.deriveChild(index);
  }
  return key;
}

// ─── ECDSA Address Derivers ─────────────────────────────────────────────────

function deriveBitcoinAddress(privKey, pubKey) {
  const h = hash160(pubKey);
  const words = bech32.toWords(h);
  words.unshift(0); // witness version 0
  return {
    address: bech32.encode("bc", words),
    wif: wifEncode(privKey, 0x80),
  };
}

function deriveLitecoinAddress(privKey, pubKey) {
  const h = hash160(pubKey);
  const words = bech32.toWords(h);
  words.unshift(0);
  return {
    address: bech32.encode("ltc", words),
    wif: wifEncode(privKey, 0xb0),
  };
}

function deriveP2PKHAddress(pubKey, versionByte) {
  const h = hash160(pubKey);
  const buf = new Uint8Array(21);
  buf[0] = versionByte;
  buf.set(h, 1);
  return b58check.encode(buf);
}

function deriveBitcoinCashAddress(privKey, pubKey) {
  return {
    address: deriveP2PKHAddress(pubKey, 0x00),
    wif: wifEncode(privKey, 0x80),
  };
}

function deriveDogecoinAddress(privKey, pubKey) {
  return {
    address: deriveP2PKHAddress(pubKey, 0x1e),
    wif: wifEncode(privKey, 0x9e),
  };
}

function deriveDashAddress(privKey, pubKey) {
  return {
    address: deriveP2PKHAddress(pubKey, 0x4c),
    wif: wifEncode(privKey, 0xcc),
  };
}

function deriveCosmosAddress(pubKey, hrp) {
  const h = hash160(pubKey);
  const words = bech32.toWords(h);
  return { address: bech32.encode(hrp, words) };
}

function deriveEthereumAddress(privKey, _pubKey) {
  // Need uncompressed pubkey for keccak
  const uncompressed = secp256k1.getPublicKey(privKey, false); // 65 bytes with 04 prefix
  const pubNoPrefix = uncompressed.slice(1); // 64 bytes
  const hash = keccak_256(pubNoPrefix);
  const addrBytes = hash.slice(12); // last 20 bytes
  const hexAddr = bytesToHex(addrBytes);
  // EIP-55 checksum
  const checksumHash = bytesToHex(keccak_256(new TextEncoder().encode(hexAddr)));
  let result = "0x";
  for (let i = 0; i < 40; i++) {
    result += parseInt(checksumHash[i], 16) >= 8 ? hexAddr[i].toUpperCase() : hexAddr[i];
  }
  return { address: result };
}

function deriveTronAddress(privKey, _pubKey) {
  const uncompressed = secp256k1.getPublicKey(privKey, false);
  const pubNoPrefix = uncompressed.slice(1);
  const hash = keccak_256(pubNoPrefix);
  const ethAddr = hash.slice(12);

  const tronAddr = new Uint8Array(21);
  tronAddr[0] = 0x41;
  tronAddr.set(ethAddr, 1);

  const firstSHA = sha256(tronAddr);
  const secondSHA = sha256(firstSHA);
  const checksum = secondSHA.slice(0, 4);

  const addrWithChecksum = new Uint8Array(25);
  addrWithChecksum.set(tronAddr);
  addrWithChecksum.set(checksum, 21);

  return { address: base58.encode(addrWithChecksum) };
}

function deriveRippleAddress(_privKey, pubKey) {
  const h = hash160(pubKey);
  const buf = new Uint8Array(21);
  buf[0] = 0x00;
  buf.set(h, 1);
  const firstSHA = sha256(buf);
  const secondSHA = sha256(firstSHA);
  const checksum = secondSHA.slice(0, 4);
  const full = new Uint8Array(25);
  full.set(buf);
  full.set(checksum, 21);
  // XRP uses a custom base58 alphabet
  const XRP_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
  return {
    address: base58
      .encode(full)
      .split("")
      .map((c) => {
        const BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        const idx = BTC_ALPHABET.indexOf(c);
        return XRP_ALPHABET[idx];
      })
      .join(""),
  };
}

// ─── EdDSA Address Derivers ─────────────────────────────────────────────────

function deriveSolanaAddress(_privKey, pubKey) {
  return { address: base58.encode(pubKey) };
}

function deriveSuiAddress(_privKey, pubKey) {
  const input = new Uint8Array(1 + pubKey.length);
  input[0] = 0x00; // ed25519 flag
  input.set(pubKey, 1);
  const hash = blake2b(input, { dkLen: 32 });
  return { address: "0x" + bytesToHex(hash) };
}

// ─── TON V4R2 Wallet Address ────────────────────────────────────────────────

const V4R2_CODE_HASH = hexToBytes(
  "feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0",
);
const V4R2_CODE_DEPTH = 7;

function tonCellHash(data, dataBits, refs) {
  const d1 = refs ? refs.length : 0;
  const d2 = Math.floor(dataBits / 8) + Math.ceil(dataBits / 8);

  // Pad data if bits don't fill last byte
  let paddedData;
  const dataBytes = Math.ceil(dataBits / 8);
  if (dataBits % 8 === 0) {
    paddedData = data.slice(0, dataBytes);
  } else {
    paddedData = new Uint8Array(dataBytes);
    paddedData.set(data.slice(0, dataBytes));
    const lastBitPos = dataBits % 8;
    // Set padding: 1 bit after last data bit, rest zeros
    paddedData[dataBytes - 1] =
      (paddedData[dataBytes - 1] & (0xff << (8 - lastBitPos))) | (1 << (7 - lastBitPos));
  }

  const parts = [new Uint8Array([d1, d2]), paddedData];
  if (refs) {
    for (const ref of refs) {
      parts.push(new Uint8Array([ref.depth >> 8, ref.depth & 0xff]));
    }
    for (const ref of refs) {
      parts.push(ref.hash);
    }
  }
  return sha256(concatBytes(...parts));
}

function crc16ccitt(data) {
  let crc = 0;
  for (const byte of data) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) {
      crc = crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1;
      crc &= 0xffff;
    }
  }
  return crc;
}

function deriveTonAddress(_privKey, pubKey) {
  // Data cell: seqno(32) + subWalletId(32) + publicKey(256) + pluginDict(1 empty) = 321 bits
  const dataBytes = new Uint8Array(41);
  const view = new DataView(dataBytes.buffer);
  view.setUint32(0, 0, false); // seqno = 0
  view.setUint32(4, 698983191, false); // subWalletId
  dataBytes.set(pubKey, 8); // pubkey 32 bytes
  // Byte 40: pluginDict=0 + padding 1 + zeros = 0x40
  dataBytes[40] = 0x40;
  const dataHash = tonCellHash(dataBytes, 321, null);

  // State init: 00110 (5 bits) = split_depth:0, special:0, code:1, data:1, library:0
  const stateData = new Uint8Array([0x34]); // 00110 + padding bit + 00 = 0x34
  const stateHash = tonCellHash(stateData, 5, [
    { hash: V4R2_CODE_HASH, depth: V4R2_CODE_DEPTH },
    { hash: dataHash, depth: 0 },
  ]);

  // User-friendly address: tag(1) + workchain(1) + hash(32) + crc16(2)
  const tag = 0x51; // non-bounceable, mainnet
  const addressData = new Uint8Array(34);
  addressData[0] = tag;
  addressData[1] = 0; // workchain 0
  addressData.set(stateHash, 2);

  const crc = crc16ccitt(addressData);
  const full = new Uint8Array(36);
  full.set(addressData);
  full[34] = crc >> 8;
  full[35] = crc & 0xff;

  // Base64url encode
  let b64 = btoa(String.fromCharCode(...full));
  b64 = b64.replace(/\+/g, "-").replace(/\//g, "_");
  return { address: b64 };
}

// ─── Coin Registry ──────────────────────────────────────────────────────────

const ECDSA_COINS = [
  // UTXO chains
  { name: "bitcoin", path: "m/84'/0'/0'/0/0", derive: deriveBitcoinAddress },
  { name: "bitcoinCash", path: "m/44'/145'/0'/0/0", derive: deriveBitcoinCashAddress },
  { name: "dogecoin", path: "m/44'/3'/0'/0/0", derive: deriveDogecoinAddress },
  { name: "litecoin", path: "m/84'/2'/0'/0/0", derive: deriveLitecoinAddress },
  { name: "dash", path: "m/44'/5'/0'/0/0", derive: deriveDashAddress },

  // Cosmos chains
  {
    name: "thorchain",
    path: "m/44'/931'/0'/0/0",
    derive: (p, pk) => deriveCosmosAddress(pk, "thor"),
  },
  {
    name: "maya",
    path: "m/44'/931'/0'/0/0",
    derive: (p, pk) => deriveCosmosAddress(pk, "maya"),
  },
  {
    name: "cosmos",
    path: "m/44'/118'/0'/0/0",
    derive: (p, pk) => deriveCosmosAddress(pk, "cosmos"),
  },
  {
    name: "osmosis",
    path: "m/44'/118'/0'/0/0",
    derive: (p, pk) => deriveCosmosAddress(pk, "osmo"),
  },
  {
    name: "kujira",
    path: "m/44'/118'/0'/0/0",
    derive: (p, pk) => deriveCosmosAddress(pk, "kujira"),
  },
  { name: "dydx", path: "m/44'/118'/0'/0/0", derive: (p, pk) => deriveCosmosAddress(pk, "dydx") },
  { name: "terra", path: "m/44'/118'/0'/0/0", derive: (p, pk) => deriveCosmosAddress(pk, "terra") },
  {
    name: "terra classic",
    path: "m/44'/118'/0'/0/0",
    derive: (p, pk) => deriveCosmosAddress(pk, "terra"),
  },
  { name: "noble", path: "m/44'/118'/0'/0/0", derive: (p, pk) => deriveCosmosAddress(pk, "noble") },
  { name: "akash", path: "m/44'/118'/0'/0/0", derive: (p, pk) => deriveCosmosAddress(pk, "akash") },

  // EVM chains (all produce the same address from m/44'/60'/0'/0/0)
  { name: "ethereum", path: "m/44'/60'/0'/0/0", derive: deriveEthereumAddress },
  { name: "avalanche", path: "m/44'/60'/0'/0/0", derive: deriveEthereumAddress },
  { name: "bsc", path: "m/44'/60'/0'/0/0", derive: deriveEthereumAddress },
  { name: "arbitrum", path: "m/44'/60'/0'/0/0", derive: deriveEthereumAddress },
  { name: "base", path: "m/44'/60'/0'/0/0", derive: deriveEthereumAddress },
  { name: "optimism", path: "m/44'/60'/0'/0/0", derive: deriveEthereumAddress },
  { name: "polygon", path: "m/44'/60'/0'/0/0", derive: deriveEthereumAddress },
  { name: "blast", path: "m/44'/60'/0'/0/0", derive: deriveEthereumAddress },
  { name: "cronos", path: "m/44'/60'/0'/0/0", derive: deriveEthereumAddress },
  { name: "zksync", path: "m/44'/60'/0'/0/0", derive: deriveEthereumAddress },
  { name: "mantle", path: "m/44'/60'/0'/0/0", derive: deriveEthereumAddress },
  { name: "hyperliquid", path: "m/44'/60'/0'/0/0", derive: deriveEthereumAddress },
  { name: "sei", path: "m/44'/60'/0'/0/0", derive: deriveEthereumAddress },

  // Other ECDSA
  { name: "tron", path: "m/44'/195'/0'/0/0", derive: deriveTronAddress },
  { name: "ripple", path: "m/44'/144'/0'/0/0", derive: deriveRippleAddress },
];

const EDDSA_COINS = [
  { name: "solana", path: "m/44'/501'/0'/0'", derive: deriveSolanaAddress },
  { name: "sui", path: "m/44'/784'/0'/0'/0'", derive: deriveSuiAddress },
  { name: "ton", path: "m/44'/607'/0'/0'/0'", derive: deriveTonAddress },
];

// ─── Public API ─────────────────────────────────────────────────────────────

export function deriveECDSACoins(privKeyHex, chainCodeHex) {
  const rootPrivKey = hexToBytes(privKeyHex);
  const rootChainCode = hexToBytes(chainCodeHex);
  const results = [];

  for (const coin of ECDSA_COINS) {
    try {
      const derived = deriveChildKey(rootPrivKey, rootChainCode, coin.path);
      const privKey = derived.privateKey;
      const pubKey = derived.publicKey;
      if (!privKey || !pubKey) continue;

      const result = coin.derive(privKey, pubKey);
      results.push({
        name: coin.name,
        derivePath: coin.path,
        address: result.address,
        hexPrivateKey: bytesToHex(privKey),
        hexPublicKey: bytesToHex(pubKey),
        wifPrivateKey: result.wif || "",
      });
    } catch {
      // skip coins that fail derivation
    }
  }

  return results;
}

// Reduce an EdDSA scalar mod L (ed25519 group order) and recompute the public key.
// DKLS Schnorr key export can return raw scalars > L that need reduction.
function processEdDSAScalar(rawPrivKey) {
  const L = ed25519.Point.Fn.ORDER;
  let scalar = BigInt("0x" + bytesToHex(rawPrivKey));
  if (scalar >= L) {
    scalar = scalar % L;
  }
  let hexScalar = scalar.toString(16).padStart(64, "0");
  const privKey = hexToBytes(hexScalar);
  const pubPoint = ed25519.Point.BASE.multiply(scalar);
  const pubKey = hexToBytes(pubPoint.toHex());
  return { privKey, pubKey };
}

export function deriveEdDSACoins(privKeyHex, _pubKeyHex) {
  const rawPrivKey = hexToBytes(privKeyHex);
  const { privKey, pubKey } = processEdDSAScalar(rawPrivKey);
  const processedPrivHex = bytesToHex(privKey);
  const processedPubHex = bytesToHex(pubKey);
  const results = [];

  for (const coin of EDDSA_COINS) {
    try {
      const result = coin.derive(privKey, pubKey);
      results.push({
        name: coin.name,
        derivePath: coin.path,
        address: result.address,
        hexPrivateKey: processedPrivHex,
        hexPublicKey: processedPubHex,
      });
    } catch {
      // skip coins that fail derivation
    }
  }

  return results;
}
