import * as crypto from "crypto";
import { canonize, JsonLdDocument } from "jsonld";
import { CompactSign, importJWK, JWK } from "jose";

export async function normalize(payload: JsonLdDocument): Promise<string> {
  return canonize(payload, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
  });
}

export function sha256(payload: string): Buffer {
  const h = crypto.createHash("sha256");
  h.update(payload);
  return h.digest();
}

// https://www.w3.org/community/reports/credentials/CG-FINAL-lds-jws2020-20220721/#jose-conformance
export function getAlg(key: JWK): string {
  if (typeof key !== "object") {
    throw new Error(`Can't determine alg from Uint8Array`);
  }

  const signatures: Record<string, Record<string, string> | string> = {
    OKP: {
      Ed25519: "EdDSA",
    },
    EC: {
      secp256k1: "ES256K",
      "P-256": "ES256",
      "P-384": "ES384",
    },
    RSA: "PS256",
  };

  if (key.kty && key.kty in signatures) {
    const s = signatures[key.kty];
    if (typeof s === "string") {
      return s;
    }
    if (key.crv && key.crv in s) {
      return s[key.crv];
    }
  }

  throw new Error(`Can't determine alg for kty ${key.kty} and crv ${key.crv}`);
}

export async function sign(jwk: JWK, payload: Uint8Array): Promise<string> {
  const key = await importJWK(jwk);
  return await new CompactSign(payload)
    .setProtectedHeader({ alg: getAlg(jwk), b64: false, crit: ["b64"] })
    .sign(key);
}
