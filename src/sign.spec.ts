import { describe, test } from "node:test";
import * as assert from "node:assert";
import * as crypto from "node:crypto";
import {
  keypair_0,
  message_0,
  signature_0,
  vc_0,
  vc_template_0,
  issuer_0,
} from "./fixtures";
import { sign } from "./sign-utils";
import { signVerifiableCredential } from ".";

describe("Specification Test Vectors", () => {
  const credential = {
    ...vc_template_0,
    issuer: {
      ...vc_template_0.issuer,
      id: issuer_0.id,
    },
  };

  test("Signing message_0 with keypair_0 should yield signature_0", async () => {
    const signed = await sign(keypair_0.privateKeyJwk, Buffer.from(message_0));
    assert.equal(signed, signature_0);
  });

  test("Signing vc_template_0 with keypair_0 should yield JWS of vc_0", async () => {
    const signed = await signVerifiableCredential(
      keypair_0.privateKeyJwk,
      vc_0.proof.verificationMethod,
      credential,
      { flavour: "Specification", created: vc_0.proof.created },
    );
    assert.equal(signed.proof.jws, vc_0.proof.jws);
  });

  test("Signing vc_template_0 with keypair_0 as PEM should yield same JWS as with JWK", async () => {
    const pem = crypto
      .createPrivateKey({ key: keypair_0.privateKeyJwk, format: "jwk" })
      .export({ type: "pkcs8", format: "pem" }) as string;

    const signed = await signVerifiableCredential(
      pem,
      vc_0.proof.verificationMethod,
      credential,
      { flavour: "Specification", created: vc_0.proof.created },
    );
    assert.equal(signed.proof.jws, vc_0.proof.jws);
  });

  test("Signing should work with .pem RSA keys", async () => {
    const { privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048, // key size in bits (2048 or 4096 recommended)
      publicKeyEncoding: {
        type: "spki",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
      },
    });

    await signVerifiableCredential(
      privateKey,
      vc_0.proof.verificationMethod,
      credential,
      { flavour: "Specification", created: vc_0.proof.created },
    );
  });
});
