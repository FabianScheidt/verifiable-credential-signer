import { JWK, JWS } from "node-jose";
import { canonize, JsonLdDocument } from "jsonld";
import * as crypto from "crypto";

interface Proof {
  type: "JsonWebSignature2020";
  created: string;
  proofPurpose: "assertionMethod";
  verificationMethod: string;
  jws: string;
}

export async function signVerifiableCredential<
  T extends Record<string, unknown>,
>(
  pemPrivateKey: string,
  verificationMethod: string,
  verifiableCredential: T,
): Promise<T & { proof: Proof }> {
  // Normalize VC
  const credentialNormalized = await normalize(verifiableCredential);
  const credentialHashed = await hash(credentialNormalized);

  // Import key
  const keystore = JWK.createKeyStore();
  const key = await keystore.add(pemPrivateKey, "pem");

  // Sign and add signature
  const signOptions: JWS.SignOptions = { format: "compact", alg: "PS256" };
  const credentialJws = await JWS.createSign(signOptions, key)
    .update(credentialHashed, "utf8")
    .final();

  return {
    ...verifiableCredential,
    proof: {
      type: "JsonWebSignature2020",
      created: new Date().toISOString(),
      proofPurpose: "assertionMethod",
      verificationMethod: verificationMethod,
      // Sign result is actually a string if the compact format is used:
      // https://github.com/cisco/node-jose#signing-content
      jws: credentialJws as unknown as string,
    },
  };
}

async function normalize(payload: JsonLdDocument) {
  return await canonize(payload, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
  });
}

async function hash(payload: string) {
  const encoder = new TextEncoder();
  const data = encoder.encode(payload);
  const digestBuffer = await crypto.subtle.digest("SHA-256", data);
  const digestArray = new Uint8Array(digestBuffer);
  return Array.from(digestArray)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
