import { JWK } from "node-jose";
import { CompactSign, importJWK } from "jose";
import { canonize, JsonLdDocument } from "jsonld";
import * as crypto from "crypto";
import { JsonLdObj } from "jsonld/jsonld-spec";

interface JsonWebSignature2020Proof {
  type: "JsonWebSignature2020";
  created: string;
  proofPurpose: "assertionMethod";
  verificationMethod: string;
  jws: string;
}

export async function signVerifiableCredential<T extends JsonLdObj>(
  pemPrivateKey: string,
  verificationMethod: string,
  verifiableCredential: T,
): Promise<T & { proof: JsonWebSignature2020Proof }> {
  // Drop potentially existing proof
  delete verifiableCredential.proof;

  // Ensure that VC context contains JsonWebKey2020
  if (!(await checkForJsonWebKey2020Context(verifiableCredential))) {
    const proofContext = "https://w3id.org/security/suites/jws-2020/v1";
    const vcContext = verifiableCredential["@context"] ?? [];
    const vcContextArray = Array.isArray(vcContext)
      ? [...vcContext, proofContext]
      : [vcContext, proofContext];
    verifiableCredential = {
      ...verifiableCredential,
      "@context": vcContextArray,
    };
  }

  // Normalize VC
  const credentialNormalized = await normalize(verifiableCredential);
  const credentialHashed = await hash(credentialNormalized);
  const credentialEncoded = new TextEncoder().encode(credentialHashed);

  // Import key using "node-jose" to support various key formats
  const keystore = JWK.createKeyStore();
  const key = await keystore.add(pemPrivateKey, "pem");

  // Sign using "jose" to support unencoded payload option according to RFC 7797
  const signKey = await importJWK(key.toJSON(true) as Record<string, unknown>);
  const credentialJws = await new CompactSign(credentialEncoded)
    .setProtectedHeader({ alg: "PS256", b64: false, crit: ["b64"] })
    .sign(signKey);

  // Add proof and return result
  return addJsonWebSignature2020Proof(
    verifiableCredential,
    verificationMethod,
    credentialJws,
  );
}

async function checkForJsonWebKey2020Context(
  verifiableCredential: JsonLdObj,
): Promise<boolean> {
  // There is probably a smarter solution, but here we simply add the required keys and see if the validation fails.
  try {
    await normalize(addJsonWebSignature2020Proof(verifiableCredential, "", ""));
  } catch (e) {
    return false;
  }
  return true;
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

function addJsonWebSignature2020Proof<T extends JsonLdObj>(
  verifiableCredential: T,
  verificationMethod: string,
  jws: string,
): T & { proof: JsonWebSignature2020Proof } {
  return {
    ...verifiableCredential,
    proof: {
      type: "JsonWebSignature2020",
      created: new Date().toISOString(),
      proofPurpose: "assertionMethod",
      verificationMethod,
      jws,
    },
  };
}
