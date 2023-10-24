# Verifiable Credential Signer

Signs arbitrary verifiable credentials and presentations.

This service exposes a single POST endpoint which accepts an arbitrary JSON-LD payload, adds the proof section and
returns the signed result.

## Configuration Options

The service is configured via environment variables.

| Configuration         | Description                                                |
|-----------------------|------------------------------------------------------------|
| `KEY`                 | PEM-formatted private key (required)                       |
| `VERIFICATION_METHOD` | Verification method to be included in the proof (required) |
| `PORT`                | Port to expose the service (defaults to 3000)              |

You can run it locally by e.g., putting your private key into a file and running:

```
KEY=$(cat key.pem) VERIFICATION_METHOD=did:web:example.com#X509-JWK2020 yarn start
```
