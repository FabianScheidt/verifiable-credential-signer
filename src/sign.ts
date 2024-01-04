import { JWK } from "node-jose";
import { CompactSign, importJWK } from "jose";
import { canonize, expand, JsonLdDocument } from "jsonld";
import * as crypto from "crypto";
import { JsonLdObj } from "jsonld/jsonld-spec";

const SIGNATURE_TYPE = "https://w3id.org/security#JsonWebSignature2020";
const CREDENTIAL_TYPE =
  "https://www.w3.org/2018/credentials#VerifiableCredential";
const PRESENTATION_TYPE =
  "https://www.w3.org/2018/credentials#VerifiablePresentation";

type Credential = JsonLdObj & {
  id: JsonLdObj["@id"];
  type: JsonLdObj["@type"];
};

interface JsonWebSignature2020Proof {
  type: "JsonWebSignature2020";
  created: string;
  proofPurpose: "assertionMethod";
  verificationMethod: string;
  jws: string;
}

export async function signVerifiableCredential<T extends Credential>(
  pemPrivateKey: string,
  verificationMethod: string,
  verifiableCredential: T,
): Promise<T & { proof: JsonWebSignature2020Proof }> {
  // Drop potentially existing proof
  delete verifiableCredential.proof;

  // Ensure that the document's type is either a credential or presentation
  const expanded = (await expand(verifiableCredential))[0];
  const eType = expanded["@type"] ?? [];
  const eTypes = Array.isArray(eType) ? eType : [eType];
  let isCredential = eTypes.includes(CREDENTIAL_TYPE);
  const isPresentation = eTypes.includes(PRESENTATION_TYPE);
  if (!isCredential && !isPresentation) {
    const type =
      verifiableCredential["type"] ?? verifiableCredential["@type"] ?? [];
    verifiableCredential["type"] = Array.isArray(type)
      ? [...type, "VerifiableCredential"]
      : [type, "VerifiableCredential"];
    delete verifiableCredential["@type"];
    isCredential = true;
  }

  // Ensure that the required contexts are present
  const [
    hasSignatureType,
    hasCredentialType,
    hasPresentationType,
    hasTypeType,
  ] = await checkContextForTypes(
    verifiableCredential,
    ["JsonWebSignature2020", SIGNATURE_TYPE],
    ["VerifiableCredential", CREDENTIAL_TYPE],
    ["VerifiablePresentation", PRESENTATION_TYPE],
    ["type", "@type"],
  );
  const context = verifiableCredential["@context"] ?? [];
  const contexts = Array.isArray(context) ? [...context] : [context];
  if (!hasSignatureType) {
    contexts.push("https://w3id.org/security/suites/jws-2020/v1");
  }
  if (
    (isCredential && !hasCredentialType) ||
    (isPresentation && !hasPresentationType) ||
    !hasTypeType
  ) {
    contexts.push("https://www.w3.org/2018/credentials/v1");
  }
  verifiableCredential["@context"] = contexts;

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

async function checkContextForTypes(
  verifiableCredential: JsonLdObj,
  ...types: [string, string][]
): Promise<boolean[]> {
  const compactTypes = types.map((t) => t[0]);
  const expandedTypes = types.map((t) => t[1]);
  const validation = (
    await expand({
      "@context": verifiableCredential["@context"],
      "@type": compactTypes,
    })
  )[0];
  return types.map((t, i) => !!validation["@type"]?.includes(expandedTypes[i]));
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

export async function addJsonWebSignature2020Proof<T extends JsonLdObj>(
  verifiableCredential: T,
  verificationMethod: string,
  jws: string,
): Promise<T & { proof: JsonWebSignature2020Proof }> {
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
