# SSL Pinning

Pinning makes a request fail unless the server presents a key you shipped with the app, so a
certificate from any other CA, including one installed on the device by a proxy, is rejected.
Each pinned domain carries its own list of SPKI SHA-256 hashes, and the rules are the same on
Android (OkHttp `CertificatePinner`) and iOS (`URLSession` server-trust evaluation).

## Configuration

Give each host its own pins with `pinnedDomains`:

```typescript
import { NetworkSecurity } from 'react-native-security-suite';

NetworkSecurity.configurePinning({
  pinnedDomains: [
    {
      domain: 'api.example.com',
      pins: [
        'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', // current key
        'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=', // backup key
      ],
    },
    {
      domain: 'example-cdn.net',
      includeSubdomains: true, // also img.example-cdn.net, a.b.example-cdn.net, …
      pins: [
        'sha256/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
        'sha256/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=',
      ],
    },
  ],
});

NetworkSecurity.installFetchInterceptor();
```

The same `pinnedDomains` array works with `NetworkSecurity.createPinnedFetch({ pinnedDomains })`
and with the legacy `fetch(url, { headers: {}, pinnedDomains })`.

| Field | Meaning |
|-------|---------|
| `domain` | A bare hostname such as `api.example.com`. Schemes, ports, paths and wildcards (`*.example.com`) are rejected; use `includeSubdomains` instead of a wildcard. Matching is case-insensitive. |
| `pins` | Base64 SHA-256 hashes of the Subject Public Key Info, with or without the `sha256/` prefix. Each must decode to 32 bytes. |
| `includeSubdomains` | `false` by default (exact host only). `true` matches the domain itself and every subdomain. |

### Legacy form: `certificates` + `validDomains`

```typescript
NetworkSecurity.configurePinning({
  certificates: ['sha256/AAAA…=', 'sha256/BBBB…='],
  validDomains: ['api.example.com', 'example-cdn.net'],
});
```

This still works, but every pin is accepted for every listed domain **and its subdomains**. If
`api.example.com` and `example-cdn.net` use different keys, a key that is only meant for the CDN
is also accepted for the API. Use `pinnedDomains` when your hosts use different keys. The two
forms can be combined; the legacy pair is treated as one `includeSubdomains: true` entry per
domain.

## How a request is checked

Once any pinning option is set:

1. **The configuration is validated before anything is sent.** A malformed domain, a pin that is
   not a 32-byte base64 hash, an empty `pins` list, an empty `pinnedDomains` array, or
   `certificates` without `validDomains` (or the reverse) fails the request with a message that
   names the bad entry.
2. **The URL must be HTTPS and its host must match a pinned domain.** Otherwise the request fails
   with `Hostname '<host>' is not in the SSL pinning domains`. `allowCleartext` is refused.
3. **The server's chain must pass normal TLS validation for that host** (trusted root, valid
   dates, matching hostname), and **a certificate in the validated chain must match one of the
   host's pins.** The leaf, an intermediate or the root can be pinned.
4. **Every redirect is checked the same way.** A redirect to plain HTTP or to a host outside the
   pinned domains fails the request instead of being followed unpinned, and a redirect to another
   pinned domain is checked against that domain's pins.

If a host matches more than one entry (for example `example.com` with `includeSubdomains` and
`api.example.com`), it accepts the pins of every matching entry.

`NetworkSecurity.installFetchInterceptor()` sends every `https://` call through the pinned
transport, so a third-party host that is not in your pinned domains is refused. If the app also
calls third-party hosts, either add them to the config with their own pins, or skip the
interceptor and use `createPinnedFetch` for your own domains.

## Extracting SPKI SHA-256 pins

```bash
# From a PEM certificate
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64

# From a live server (pins the leaf; add -showcerts to see intermediates)
openssl s_client -connect api.example.com:443 -servername api.example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

Run this once for **each** domain you pin. Pin the public key (SPKI), not the certificate
fingerprint: a renewed certificate that keeps the same key pair still matches. RSA and EC
(P-256, P-384, P-521) keys are supported on both platforms.

iOS also accepts a SHA-256 of the whole DER certificate, for backward compatibility. Android
does not, so cross-platform apps should use SPKI pins only.

## Pin rotation

1. Ship an app update that lists both the current key and the next key (the backup) for the domain.
2. Rotate the server to the backup key.
3. In a later release, promote the backup to current and add a new backup.
4. Keep the old pin until the release that dropped it has reached nearly all of your users.

Rotate each domain independently. With `pinnedDomains`, changing one host's pins does not affect
the others.

## Error handling

Pinning failures reject the request with a message string, for example:

| Platform | Message |
|----------|---------|
| Both | `Hostname 'x' is not in the SSL pinning domains` (request URL not pinned) |
| Android | `Certificate pinning failure!` followed by the peer chain (OkHttp), or `SSL pinning: host 'x' is not in the SSL pinning domains` / `SSL pinning: refusing cleartext request to 'x'` for a redirect |
| iOS | `SSL pinning: no certificate in the chain for 'x' matches a configured pin`, `SSL pinning: the certificate chain for 'x' is not trusted`, `SSL pinning: host 'x' is not in the SSL pinning domains`, or `SSL pinning: refusing cleartext redirect to 'x'` |

Fail closed: show an error or ask the user to update the app. Never retry the same request
without pinning.

## Common mistakes

| Mistake | Fix |
|---------|-----|
| Pinning the certificate fingerprint instead of SPKI | Use the SPKI command above |
| A single pin with no backup | Always ship a backup key per domain |
| Sharing one pin list across unrelated domains | Use `pinnedDomains` so each host only accepts its own keys |
| Writing `*.example.com` or `https://api.example.com` as the domain | Use the bare hostname, plus `includeSubdomains: true` if needed |
| Forgetting a host the app redirects to | Pin every host in the redirect chain |
| Pinning `localhost` in production | Keep separate dev and prod configs |

## Testing

- Point the app at [mitmproxy](https://mitmproxy.org/) or Charles: pinned requests **must** fail.
- Before rotating a server key, confirm in staging that the backup pin is accepted.
- Test each pinned domain separately, including any host reached through a redirect.
