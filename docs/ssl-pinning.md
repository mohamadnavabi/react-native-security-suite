# SSL Pinning Best Practices

## Configuration

```typescript
import { SecureNetwork } from 'react-native-security-suite';

await SecureNetwork.fetch('https://api.example.com/v1/accounts', {
  method: 'GET',
  headers: { Accept: 'application/json' },
  sslPinning: {
    validDomains: ['api.example.com'],
    pins: {
      primary: [
        'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      ],
      backup: [
        'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
      ],
    },
    certificateTransparency: false, // optional, adds network call
  },
});
```

## Extracting SPKI SHA-256 pins

```bash
# From a PEM certificate
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64

# From live server
openssl s_client -connect api.example.com:443 -servername api.example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

Pin the **Subject Public Key Info (SPKI)** hash, not the certificate fingerprint. Public key pinning survives cert renewal with the same key pair.

## Pin rotation strategy

1. Deploy app update with **both** old (primary) and new (backup) pins
2. Rotate server certificate to match backup pin
3. Next app release: promote new pin to primary, add next backup
4. Never remove the last pin before the new app version reaches >95% adoption

## Domain allowlists

- Always set `validDomains` — pinning without domain restriction is rejected
- Use exact hostnames; wildcard subdomains require explicit entries:

```typescript
validDomains: ['api.example.com', 'cdn.example.com']
```

## Error handling

```typescript
try {
  await SecureNetwork.fetch(url, options);
} catch (error) {
  if (error.code === 'SSL_PINNING_FAILED') {
    // { code, domain, reason }
    // reason: 'PIN_MISMATCH' | 'DOMAIN_NOT_ALLOWED' | 'CERT_CHAIN_INVALID'
    analytics.track('ssl_pin_failure', { domain: error.domain });
    showError('Secure connection failed. Please update the app.');
  }
}
```

## Common mistakes

| Mistake | Fix |
|---------|-----|
| Pinning leaf cert hash instead of SPKI | Use SPKI SHA-256 |
| Single pin with no backup | Always ship backup pin |
| Pinning `localhost` in production | Separate dev/prod configs |
| Disabling pinning when it fails | Fail closed; never bypass in prod |
| Using HTTP | Library rejects non-HTTPS URLs |

## Certificate Transparency (optional)

When enabled, the library validates SCT presence in the certificate. Requires network access to CT logs on first connect. Recommended for high-security deployments; may add 100–300ms latency.

## Testing

- Use [mitmproxy](https://mitmproxy.org/) in dev — pinning **should** fail
- Verify backup pin acceptance before cert rotation in staging
- Test corporate proxy scenarios if your users are enterprise
