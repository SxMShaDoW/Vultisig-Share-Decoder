
// Protobuf schema definitions for Vultisig vault structures
// Based on vultisig/commondata protobuf definitions using @bufbuild/protobuf

import { proto3 } from "@bufbuild/protobuf";

// VaultContainer message
export const VaultContainerSchema = proto3.makeMessageType(
  "vultisig.vault.v1.VaultContainer",
  () => [
    { no: 1, name: "version", kind: "scalar", T: 4 /* ScalarType.UINT64 */ },
    { no: 2, name: "vault", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 3, name: "is_encrypted", kind: "scalar", T: 8 /* ScalarType.BOOL */ },
  ],
);

// Vault.KeyShare nested message
export const VaultKeyShareSchema = proto3.makeMessageType(
  "vultisig.vault.v1.Vault.KeyShare", 
  () => [
    { no: 1, name: "public_key", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "keyshare", kind: "scalar", T: 9 /* ScalarType.STRING */ },
  ],
);

// Main Vault message
export const VaultSchema = proto3.makeMessageType(
  "vultisig.vault.v1.Vault",
  () => [
    { no: 1, name: "name", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "public_key_ecdsa", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 3, name: "public_key_eddsa", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 4, name: "signers", kind: "scalar", T: 9 /* ScalarType.STRING */, repeated: true },
    { no: 5, name: "created_at", kind: "message", T: () => import("@bufbuild/protobuf/wkt").TimestampSchema },
    { no: 6, name: "hex_chain_code", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 7, name: "key_shares", kind: "message", T: VaultKeyShareSchema, repeated: true },
    { no: 8, name: "local_party_id", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 9, name: "reshare_prefix", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 10, name: "lib_type", kind: "scalar", T: 5 /* ScalarType.INT32 */ },
  ],
);

// LibType enum values
export const LibType = {
  GG20: 0,
  DKLS: 1,
};
