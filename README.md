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

| Configuration         | Description                                                |
| --------------------- | ---------------------------------------------------------- |
| `KEY`                 | PEM-formatted private key (required)                       |
| `VERIFICATION_METHOD` | Verification method to be included in the proof (required) |
| `PORT`                | Port to expose the service (defaults to 3000)              |

You can run it locally by e.g., putting your private key into a file and running:

```
KEY=$(cat key.pem) VERIFICATION_METHOD=did:web:example.com#X509-JWK2020 yarn start
```

## Deployment

If you use Docker, there is a prebuilt image available, which is kept up to date with this repository:
[fabisch/verifiable-credential-signer:latest](https://hub.docker.com/r/fabisch/verifiable-credential-signer)
