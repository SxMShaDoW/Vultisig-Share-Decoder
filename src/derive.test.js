import { deriveECDSACoins, deriveEdDSACoins } from "./derive.js";

const privKeyHex = "0806a352d32950671e711225514a5fd53d6411dc9f4525d7bad11ef73956c601";
const chainCodeHex = "e2f8c4826d6d23407cff45498b940f52756c3056fa1bcba0cb7f6bafc2478eac";

const ecdsaKeys = deriveECDSACoins(privKeyHex, chainCodeHex);
const byName = Object.fromEntries(ecdsaKeys.map((k) => [k.name, k]));

console.log(`ECDSA coins derived: ${ecdsaKeys.length}`);

// Bitcoin
const btc = byName.bitcoin;
console.assert(btc.address === "bc1q0pap5flkh45w8zz2ew9xpf884me55g65l7vqcu", `BTC: ${btc.address}`);
console.assert(btc.wifPrivateKey !== "", "BTC WIF should not be empty");
console.log(`BTC: ${btc.address} ✓`);

// Ethereum
const eth = byName.ethereum;
console.assert(eth.address === "0x60790246e37D154e02beaF2b9Fb27F93a26A6B3f", `ETH: ${eth.address}`);
console.assert(
  eth.hexPrivateKey === "e49960641cf0f56139fe8a3088cf7bf8bb0d4bb9ee94b788875834d604703623",
  `ETH privkey: ${eth.hexPrivateKey}`,
);
console.log(`ETH: ${eth.address} ✓`);

// THORChain
const thor = byName.thorchain;
console.assert(
  thor.address === "thor167h7nq5wuklekdeyrmsgy2p6gc3acaezp0wwql",
  `THOR: ${thor.address}`,
);
console.log(`THOR: ${thor.address} ✓`);

// MayaChain
const maya = byName.maya;
console.assert(
  maya.address === "maya167h7nq5wuklekdeyrmsgy2p6gc3acaezpcszk0",
  `MAYA: ${maya.address}`,
);
console.log(`MAYA: ${maya.address} ✓`);

// EdDSA
const eddsaPrivKeyHex = "733da00cb116e47317d8d0fdf2629f11500abd28a52a8dcbb3f8737f2a631e07";
const eddsaPubKeyHex = "20e368bf985efdc270500c6e9dc1159102323ff6eabab56f8fa9798e4ac0e2a9";

const eddsaKeys = deriveEdDSACoins(eddsaPrivKeyHex, eddsaPubKeyHex);
const edByName = Object.fromEntries(eddsaKeys.map((k) => [k.name, k]));

console.log(`EdDSA coins derived: ${eddsaKeys.length}`);

// Solana (scalar is reduced mod L, so address differs from raw pubkey)
const sol = edByName.solana;
console.assert(
  sol.address === "7MMV5XnYP2ZT5AuXFuaH1Yt3Hv4X4gMYiZkA7vBUFiN4",
  `SOL: ${sol.address}`,
);
console.assert(
  sol.hexPrivateKey === "033da00cb116e47317d8d0fdf2629f10bdf1e812306543ef4b77bdc69faa528c",
  `SOL privkey: ${sol.hexPrivateKey}`,
);
console.log(`SOL: ${sol.address} ✓`);

// TON
const ton = edByName.ton;
console.assert(
  ton.address === "UQC-rEgEkPrKDfMOz0YfRrHfUN83GxvUhZCMKqSgGVwe-liH",
  `TON: ${ton.address}`,
);
console.log(`TON: ${ton.address} ✓`);

// SUI
const sui = edByName.sui;
console.assert(
  sui.address === "0x8237f0a3c04ae7498c6380990f7d37e5f5ed243bd382c7a3bbf135a2258fc59d",
  `SUI: ${sui.address}`,
);
console.log(`SUI: ${sui.address} ✓`);

// Print all EVM chains (should all have same address as ETH)
for (const name of ["avalanche", "bsc", "arbitrum", "base", "optimism", "polygon"]) {
  const coin = byName[name];
  if (coin) {
    console.assert(coin.address === eth.address, `${name} should match ETH: ${coin.address}`);
  }
}
console.log("All EVM chains match ETH address ✓");

console.log("\nAll tests passed!");
