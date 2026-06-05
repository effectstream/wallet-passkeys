import { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { registerPasskey, authenticatePasskey, authorizeAccessKey } from "@/lib/passkey";
import { getOrCreateAccessKey, saveAuthorization, type AccessKey } from "@/lib/access-key";
import { publicKeyToDid, buildDidDocument } from "@/lib/did";

function postToParent(type: string, payload: unknown) {
  if (window.parent !== window) {
    window.parent.postMessage({ source: "midnightos-passkeys", type, payload }, "*");
  }
}

// NOTE: The previous version of this hook used IntersectionObserver with
// {trackVisibility: true} as a clickjacking check. In practice that API is an
// experimental Chrome-only feature with frequent false positives — any iframe
// with a non-trivial border / box-shadow / transform on its container can be
// reported as "obscured" even when it's fully visible. We disable the check
// here and instead rely on CSP `frame-ancestors *` plus per-message origin
// pinning on the postMessage side for security.
function useVisibilityCheck() {
  const containerRef = useRef<HTMLDivElement>(null);
  return { containerRef, visible: true, supported: false };
}

function rawToDer(raw: Uint8Array): string {
  const r = raw.slice(0, 32);
  const s = raw.slice(32, 64);

  function encodeInteger(bytes: Uint8Array): number[] {
    // Trim leading zeros but keep at least one byte
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    const trimmed = bytes.slice(start);
    // Pad with 0x00 if high bit is set (negative in ASN.1)
    const pad = trimmed[0]! & 0x80 ? [0x00] : [];
    const value = [...pad, ...trimmed];
    return [0x02, value.length, ...value];
  }

  const rEnc = encodeInteger(r);
  const sEnc = encodeInteger(s);
  const body = [...rEnc, ...sEnc];
  const der = [0x30, body.length, ...body];

  return der.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function signMessage(
  privateKey: CryptoKey,
  message: string,
): Promise<{ raw: string; der: string }> {
  const encoded = new TextEncoder().encode(message);
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    encoded,
  );
  const bytes = new Uint8Array(signature);
  const raw =
    "0x" + [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  const der = rawToDer(bytes);
  return { raw, der };
}

function truncateDid(did: string): string {
  // did:key:zABC…XYZ — show a wallet-style truncated identity
  const z = did.replace("did:key:", "");
  if (z.length <= 18) return did;
  return `did:key:${z.slice(0, 10)}…${z.slice(-8)}`;
}

export function EmbedAuth() {
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [username, setUsername] = useState("midnight-user");
  const [identityDid, setIdentityDid] = useState<string | null>(null);
  const { containerRef, visible, supported } = useVisibilityCheck();
  const accessKeyRef = useRef<AccessKey | null>(null);

  const obscured = supported && !visible;

  // Full-height popup layout for the /embed route.
  useEffect(() => {
    document.documentElement.classList.add("embed");
    return () => document.documentElement.classList.remove("embed");
  }, []);

  // Listen for commands from the parent
  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      const data = event.data;
      if (data?.source !== "midnightos-dapp") return;

      if (data.type === "register") {
        handleRegister(data.payload?.username ?? "midnight-user");
      } else if (data.type === "sign-in") {
        handleSignIn(data.payload?.credentialId);
      } else if (data.type === "sign") {
        handleSign(data.payload?.message, data.payload?.requestId);
      }
    }
    window.addEventListener("message", handleMessage);
    return () => window.removeEventListener("message", handleMessage);
  });

  function handleClose() {
    // Ask the parent dApp to dismiss the floating popup.
    postToParent("close", {});
  }

  async function handleSign(message: string, requestId?: string) {
    const key = accessKeyRef.current;
    if (!key) {
      postToParent("sign-error", {
        requestId,
        error: "No access key available. Authenticate first.",
      });
      return;
    }
    try {
      const { raw, der } = await signMessage(key.privateKey, message);
      postToParent("signed", {
        requestId,
        message,
        signature: raw,
        signatureDer: der,
        publicKey: key.publicKeyHex,
      });
    } catch (e) {
      postToParent("sign-error", {
        requestId,
        error: e instanceof Error ? e.message : "Signing failed",
      });
    }
  }

  const handleRegister = useCallback(
    async (name?: string) => {
      if (obscured) {
        window.open(window.location.href.replace("/embed", ""), "_blank");
        return;
      }
      setLoading(true);
      setError(null);
      try {
        const cred = await registerPasskey(name ?? username);
        const accessKey = await getOrCreateAccessKey(cred.credentialId);

        // Passkey signs a challenge containing the access key's public key
        // This is the cryptographic proof of delegation (key authorization)
        const authorization = await authorizeAccessKey(
          cred.credentialId,
          accessKey.publicKeyHex,
        );
        await saveAuthorization(cred.credentialId, authorization);
        accessKey.authorization = authorization;

        accessKeyRef.current = accessKey;
        const did = publicKeyToDid(accessKey.publicKeyCompressed);
        const didDocument = buildDidDocument(did, accessKey.publicKeyRaw);

        postToParent("authenticated", {
          credential: cred,
          did,
          didDocument,
          accessKeyPublicKey: accessKey.publicKeyHex,
          keyAuthorization: authorization,
        });
        setIdentityDid(did);
        setDone(true);
      } catch (e) {
        const msg = e instanceof Error ? e.message : "Registration failed";
        setError(msg);
        postToParent("error", { message: msg });
      } finally {
        setLoading(false);
      }
    },
    [username, obscured],
  );

  const handleSignIn = useCallback(
    async (credentialId?: string) => {
      if (obscured) {
        window.open(window.location.href.replace("/embed", ""), "_blank");
        return;
      }
      setLoading(true);
      setError(null);
      try {
        const cred = await authenticatePasskey(credentialId);
        const accessKey = await getOrCreateAccessKey(cred.credentialId);

        // If we don't have an authorization yet, get one
        let authorization = accessKey.authorization;
        if (!authorization) {
          authorization = await authorizeAccessKey(
            cred.credentialId,
            accessKey.publicKeyHex,
          );
          await saveAuthorization(cred.credentialId, authorization);
          accessKey.authorization = authorization;
        }

        accessKeyRef.current = accessKey;
        const did = publicKeyToDid(accessKey.publicKeyCompressed);
        const didDocument = buildDidDocument(did, accessKey.publicKeyRaw);

        postToParent("authenticated", {
          credential: cred,
          did,
          didDocument,
          accessKeyPublicKey: accessKey.publicKeyHex,
          keyAuthorization: authorization,
        });
        setIdentityDid(did);
        setDone(true);
      } catch (e) {
        const msg = e instanceof Error ? e.message : "Sign in failed";
        setError(msg);
        postToParent("error", { message: msg });
      } finally {
        setLoading(false);
      }
    },
    [obscured],
  );

  useEffect(() => {
    postToParent("ready", {});
  }, []);

  // ── Header (shared) ───────────────────────────────────────────────────
  const header = (
    <header className="wallet-header">
      <div className="mark">ES</div>
      <div>
        <div className="title">EffectStream Passkeys</div>
        <div className="subtitle">wallet · auth provider</div>
      </div>
      <span className={`wallet-status${done ? " live" : ""}`}>
        {done ? "connected" : "locked"}
      </span>
    </header>
  );

  // ── Connected (done) state ──────────────────────────────────────────────
  if (done) {
    return (
      <div ref={containerRef} className="wallet-shell">
        {header}
        <div className="wallet-body">
          <div className="wallet-approve">
            <div className="req-title">
              <span style={{ color: "oklch(0.86 0.27 145)" }}>✓</span> Wallet connected
            </div>
            <div className="req-detail">
              Access key is active. The dApp can now request signatures without a
              new biometric prompt.
            </div>
          </div>

          {identityDid && (
            <div className="wallet-account">
              <div className="label">Identity (did:key)</div>
              <div className="value">{truncateDid(identityDid)}</div>
            </div>
          )}

          <p className="text-xs text-muted-foreground uppercase tracking-[0.18em]">
            wallet-passkeys.ac-edward.workers.dev
          </p>
        </div>
        <footer className="wallet-footer">
          <Button onClick={handleClose}>OK</Button>
        </footer>
      </div>
    );
  }

  // ── Unauthenticated state ─────────────────────────────────────────────
  return (
    <div ref={containerRef} className="wallet-shell">
      {header}
      <div className="wallet-body">
        <div className="wallet-approve">
          <div className="req-title">Connection request</div>
          <div className="req-detail">
            A dApp wants you to connect a passkey-backed wallet. Register a new
            passkey or sign in with an existing one. No seed phrase, no extension.
          </div>
        </div>

        {obscured && (
          <p className="text-xs text-destructive font-medium">
            [WARN] iframe obscured · auth will open in a new window
          </p>
        )}

        <div className="space-y-1">
          <label
            htmlFor="embed-username"
            className="text-xs text-muted-foreground uppercase tracking-wider"
          >
            username
          </label>
          <input
            id="embed-username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="flex h-9 w-full rounded-none border border-border bg-background px-3 py-1 text-sm font-mono"
          />
        </div>

        {error && <p className="text-xs text-destructive">[ERR] {error}</p>}
      </div>

      <footer className="wallet-footer">
        <Button variant="outline" onClick={handleClose} disabled={loading}>
          Cancel
        </Button>
        <Button
          variant="outline"
          onClick={() => handleSignIn()}
          disabled={loading}
        >
          {loading ? "Waiting…" : "Sign In"}
        </Button>
        <Button onClick={() => handleRegister()} disabled={loading || !username}>
          {loading ? "Waiting…" : "Register"}
        </Button>
      </footer>
    </div>
  );
}
