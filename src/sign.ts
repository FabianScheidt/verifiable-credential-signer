import * as nodeJose from "node-jose";
import { JWK } from "jose";
import { expand } from "jsonld";
import { JsonLdObj } from "jsonld/jsonld-spec";
import { normalize, sha256, sign } from "./sign-utils";

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
  privateKey: string | JWK,
  verificationMethod: string,
  verifiableCredential: T,
  options?: { flavour?: "Specification" | "Gaia-X"; created?: string },
): Promise<T & { proof: JsonWebSignature2020Proof }> {
  // Create copy and drop potentially existing proof
  verifiableCredential = { ...verifiableCredential };
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

  // Create normalized proof
  const created = options?.created ?? new Date().toISOString();
  const proof: Record<string, unknown> = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    ...getJsonWebSignature2020Proof(verificationMethod, "", created),
  };
  delete proof.jws;
  const proofNormalized = await normalize(proof);

  let payload: Uint8Array;
  switch (options?.flavour) {
    case "Gaia-X":
      const hashed = sha256(credentialNormalized);
      payload = new TextEncoder().encode(hashed.toString("hex"));
      break;
    case "Specification":
    default:
      payload = Buffer.concat([
        sha256(proofNormalized),
        sha256(credentialNormalized),
      ]);
      break;
  }

  // Optionally import key using "node-jose" to support PEM key formats
  let jwk: JWK;
  if (typeof privateKey === "string") {
    const keystore = nodeJose.JWK.createKeyStore();
    const key = await keystore.add(privateKey, "pem");
    jwk = key.toJSON(true) as JWK;
  } else {
    jwk = privateKey;
  }

  // Sign using "jose" to support unencoded payload option according to RFC 7797
  const credentialJws = await sign(jwk, payload);

  // Add proof and return result
  return addJsonWebSignature2020Proof(
    verifiableCredential,
    verificationMethod,
    credentialJws,
    created,
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

export function addJsonWebSignature2020Proof<T extends JsonLdObj>(
  verifiableCredential: T,
  verificationMethod: string,
  jws: string,
  created: string,
): T & { proof: JsonWebSignature2020Proof } {
  return {
    ...verifiableCredential,
    proof: getJsonWebSignature2020Proof(verificationMethod, jws, created),
  };
}

export function getJsonWebSignature2020Proof(
  verificationMethod: string,
  jws: string,
  created: string,
): JsonWebSignature2020Proof {
  return {
    type: "JsonWebSignature2020",
    created,
    proofPurpose: "assertionMethod",
    verificationMethod,
    jws,
  };
}
