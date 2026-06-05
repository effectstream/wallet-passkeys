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

function useVisibilityCheck() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(true);
  const [supported, setSupported] = useState(false);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    try {
      const observer = new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            if ("isVisible" in entry) {
              setSupported(true);
              setVisible(entry.isVisible as boolean);
            }
          }
        },
        {
          threshold: [1.0],
          trackVisibility: true,
          delay: 100,
        } as IntersectionObserverInit,
      );

      observer.observe(el);
      return () => observer.disconnect();
    } catch {
      setSupported(false);
      setVisible(true);
    }
  }, []);

  return { containerRef, visible, supported };
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

export function EmbedAuth() {
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [username, setUsername] = useState("midnight-user");
  const { containerRef, visible, supported } = useVisibilityCheck();
  const accessKeyRef = useRef<AccessKey | null>(null);

  const obscured = supported && !visible;

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

  if (done) {
    return (
      <div ref={containerRef}>
        <div className="terminal-prompt">wallet-passkeys connect --status</div>
        <div className="p-4 space-y-2">
          <p className="text-sm font-medium">
            <span style={{ color: "oklch(0.86 0.27 145)" }}>[OK]</span> Authenticated
          </p>
          <p className="text-xs text-muted-foreground">
            access-key active · listening for sign requests
          </p>
        </div>
      </div>
    );
  }

  return (
    <div ref={containerRef}>
      <div className="terminal-prompt">wallet-passkeys connect</div>
      <div className="p-4 space-y-3">
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
            className="flex h-8 w-full rounded-none border border-border bg-background px-3 py-1 text-sm font-mono"
          />
        </div>
        {error && <p className="text-xs text-destructive">[ERR] {error}</p>}
        <div className="flex gap-2">
          <Button
            onClick={() => handleRegister()}
            disabled={loading || !username}
          >
            {loading ? "Waiting…" : "Register"}
          </Button>
          <Button
            variant="outline"
            onClick={() => handleSignIn()}
            disabled={loading}
          >
            {loading ? "Waiting…" : "Sign In"}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground uppercase tracking-[0.18em]">
          wallet-passkeys.ac-edward.workers.dev
        </p>
      </div>
    </div>
  );
}
