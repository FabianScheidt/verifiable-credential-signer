# Verifiable Credential Signer

Signs verifiable credentials and verifiable presentations according to the
[JSON Web Signature 2020](https://www.w3.org/community/reports/credentials/CG-FINAL-lds-jws2020-20220721/) specification.

Verifiable credentials contain a proof section, which contains a cryptographic signature of the credential's contents.
This service exposes a single POST endpoint which accepts an arbitrary verifiable credential as payload, adds the proof
section according to the JSON Web Signature 2020 specification and returns the signed result.

The endpoint is exposed with no path prefix. If you prefer to access the service with a certain prefix, configure your
load balancer accordingly. In any case, you should not expose this service publicly, as the endpoint has no protection.

## Configuration Options

The service is configured via environment variables.

| Configuration               | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `KEY`                       | PEM-formatted private key (required)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `VERIFICATION_METHOD`       | Verification method to be included in the proof (required)                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `PORT`                      | Port to expose the service (defaults to 3000)                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `DEFAULT_SIGNATURE_FLAVOUR` | The specification is not explicit about how the signature payload is assembled. As a consequence, services related to "Gaia-X" have implemented a suite that differs from other implementations. This setting configures which "flavour" to use. Possible values are "Specification" to match the provided test vectors and "Gaia-X". The default of the HTTP API is "Gaia-X", to not introduce a breaking change in this realm. The setting can be overridden per request by setting the `X-Signature-Flavour` header. |

You can run it locally by e.g., putting your private key into a file and running:

```
KEY=$(cat key.pem) VERIFICATION_METHOD=did:web:example.com#X509-JWK2020 npm run start
```

## Running Tests

You can execute the available unit tests by running:

```
npm run test
```

## Deployment

If you use Docker, there is a prebuilt image available, which is kept up to date with this repository:
[fabisch/verifiable-credential-signer:latest](https://hub.docker.com/r/fabisch/verifiable-credential-signer)

## Usage as Package

The signing functionality can also be used through an npm package:
[@fabianscheidt/verifiable-credential-signer](https://www.npmjs.com/package/@fabianscheidt/verifiable-credential-signer)
