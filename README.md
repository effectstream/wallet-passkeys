# wallet-passkeys

A passkey-backed authentication provider for EffectStream applications. Hosted as
a single Cloudflare Worker that serves both a React UI and a `/api/*` backend.
Designed to be embedded as a cross-origin iframe inside any dApp so the dApp can
let a user sign in with a passkey and receive a `did:key` identity plus a
delegated access key that can sign messages on their behalf without re-prompting
biometrics on every interaction.

**Live deployment**: <https://wallet-passkeys.ac-edward.workers.dev>

Embed entry point (for dApps): <https://wallet-passkeys.ac-edward.workers.dev/embed>

This is a fork of [`rvcas/passkeys`](https://github.com/rvcas/passkeys), adapted
to run on the EffectStream Cloudflare account with EffectStream's own KV
namespaces and worker URL.

## What it does

The user flow, end to end:

1. The dApp embeds `wallet-passkeys/embed` as an iframe.
2. The embed asks the OS to create (or use) a platform passkey via the WebAuthn
   API. The passkey's public key is stored on the worker; the private key never
   leaves the device's secure enclave.
3. The embed generates an in-browser P-256 ECDSA "access key" and asks the
   passkey to sign a challenge that *commits to that access key's public key*.
   The worker verifies the passkey signature and stores the (root passkey,
   access key) authorization tuple.
4. The embed `postMessage`s back to the parent dApp with the user's `did:key`
   identity and the access key's public key.
5. Subsequent sign requests from the dApp (`{ type: "sign", payload: { message } }`)
   are signed silently by the access key — no biometric prompt.

The whole thing is a passkey-rooted delegation system. The passkey is the
identity; the access key is a per-session signer authorized by the passkey.

## Architecture

```
┌──────────── dApp at any origin ────────────────┐
│  <iframe src="…/embed"> ── postMessage RPC ──▶ │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌──────────── Cloudflare Worker (this repo) ──────┐
│  React SPA at  /            (the standalone UI) │
│  React SPA at  /embed       (iframe-targeted)   │
│  POST          /api/register/{options,verify}   │
│  POST          /api/auth/{options,verify}       │
│  POST          /api/authorize-key/{options,verify} │
│  KV bindings:                                   │
│    CHALLENGES   — TTL'd per-session challenges  │
│    CREDENTIALS  — long-lived passkey public keys│
│                   + access-key authorizations   │
└─────────────────────────────────────────────────┘
```

Source layout:

```
src/
├── App.tsx              routes / vs /embed
├── main.tsx             React entry
├── components/
│   ├── passkey-demo.tsx   standalone demo UI at /
│   ├── embed-auth.tsx     iframe-targeted UI at /embed
│   └── steps/did-step.tsx renders the user's did:key
└── lib/
    ├── passkey.ts       WebAuthn create/get via webauthx, plus authorize-key
    ├── access-key.ts    in-browser P-256 keypair generation + localStorage
    ├── did.ts           did:key:z<…> with multicodec p256-pub prefix
    ├── api.ts           fetch wrappers for the worker endpoints
    └── session.ts       credential persistence in localStorage

worker/
├── index.ts             route dispatch + CORS + frame-ancestors: *
└── routes/
    ├── register.ts      handle WebAuthn create() flow (options + verify)
    ├── authenticate.ts  handle WebAuthn get() flow (options + verify)
    └── authorize-key.ts sign + verify the access-key delegation
```

## Local development

```sh
pnpm install
pnpm dev
# Vite+ dev server at http://localhost:5173 (or whatever vp picks)
```

The dev server runs both the React app and the Cloudflare Worker locally via
`@cloudflare/vite-plugin`. KV is emulated against `.wrangler/state/`.

## Build + deploy

```sh
pnpm run build       # tsc + vp build → dist/
pnpm run deploy      # builds + wrangler deploy
```

The deploy targets the EffectStream Cloudflare account (`28ea08e36bc67a4f136df373255ce175`)
via [wrangler.jsonc](./wrangler.jsonc). The worker binding name is
`wallet-passkeys`, so the workers.dev URL is
<https://wallet-passkeys.ac-edward.workers.dev>.

KV namespaces (already created on the deploy account):

| Binding | Namespace ID |
|---|---|
| `CHALLENGES` | `11f31ec5555e4f58afc922748bff0438` |
| `CREDENTIALS` | `ecc0c8045cbe47c5bf542521ec5940d7` |

To deploy to a different Cloudflare account: create new KV namespaces
(`wrangler kv namespace create CHALLENGES --preview false`, same for
CREDENTIALS), update `account_id` and the namespace IDs in `wrangler.jsonc`,
then `pnpm run deploy`.

## How to test

### Standalone UI

Visit <https://wallet-passkeys.ac-edward.workers.dev/>. Click **Register**,
approve the OS biometric prompt. You'll see your `did:key:z…` identity and the
JSON DID Document.

### As an embedded iframe

The companion repo
[`effectstream/wallet-passkeys-app`](https://github.com/effectstream/wallet-passkeys-app)
ships a third-party dApp that mounts this worker's `/embed` route in an iframe
and exercises the full postMessage protocol (`register`, `sign-in`, `sign`).
Live at <https://wallet-passkeys-app.ac-edward.workers.dev>.

Manually:

```html
<iframe
  src="https://wallet-passkeys.ac-edward.workers.dev/embed"
  allow="publickey-credentials-create; publickey-credentials-get"
></iframe>
<script>
  const ORIGIN = "https://wallet-passkeys.ac-edward.workers.dev";
  window.addEventListener("message", (e) => {
    if (e.origin !== ORIGIN) return;
    if (e.data?.source === "midnightos-passkeys" && e.data.type === "authenticated") {
      console.log("got did:key", e.data.payload.did);
    }
  });
  // Trigger register from a user click:
  document.querySelector("iframe").contentWindow.postMessage(
    { source: "midnightos-dapp", type: "register", payload: { username: "alice" } },
    ORIGIN,
  );
</script>
```

## Notes on security

* The access key's *private* JWK is stored in `localStorage` on the embed
  origin. An XSS at this origin can exfiltrate it. This is a deliberate trade
  for silent signing.
* The worker sets `Content-Security-Policy: frame-ancestors *` to allow any
  origin to embed it. Anti-clickjacking is handled inside the iframe via an
  `IntersectionObserver(trackVisibility:true)` check.
* Worker traffic uses `Access-Control-Allow-Origin: <request origin>` for the
  CORS preflight, so any dApp can call the `/api/*` endpoints from within an
  iframe at this origin.

## License

Same as the upstream project. See [LICENSE](./LICENSE) once added.
