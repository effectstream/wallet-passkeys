import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { PasskeyCredential } from "@/lib/passkey";
import { registerPasskey, authenticatePasskey, authorizeAccessKey } from "@/lib/passkey";
import { getOrCreateAccessKey, saveAuthorization, type AccessKey } from "@/lib/access-key";
import { saveCredential, loadCredential, clearCredential } from "@/lib/session";
import { DidStep } from "@/components/steps/did-step";

export function PasskeyDemo() {
  const [credential, setCredential] = useState<PasskeyCredential | null>(null);
  const [accessKey, setAccessKey] = useState<AccessKey | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [username, setUsername] = useState("midnight-user");

  useEffect(() => {
    const stored = loadCredential();
    if (stored) setCredential(stored);
  }, []);

  const handleRegister = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const cred = await registerPasskey(username);
      saveCredential(cred);
      const key = await getOrCreateAccessKey(cred.credentialId);
      const auth = await authorizeAccessKey(cred.credentialId, key.publicKeyHex);
      await saveAuthorization(cred.credentialId, auth);
      key.authorization = auth;
      setCredential(cred);
      setAccessKey(key);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Registration failed");
    } finally {
      setLoading(false);
    }
  }, [username]);

  const handleSignIn = useCallback(async () => {
    const stored = credential ?? loadCredential();
    setLoading(true);
    setError(null);
    try {
      // Pass credentialId if we have one, otherwise let the browser
      // show the discoverable credential picker
      const cred = await authenticatePasskey(stored?.credentialId);
      saveCredential(cred);
      const key = await getOrCreateAccessKey(cred.credentialId);
      if (!key.authorization) {
        const auth = await authorizeAccessKey(cred.credentialId, key.publicKeyHex);
        await saveAuthorization(cred.credentialId, auth);
        key.authorization = auth;
      }
      setCredential(cred);
      setAccessKey(key);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Sign in failed");
    } finally {
      setLoading(false);
    }
  }, [credential]);

  function handleLogout() {
    clearCredential();
    setCredential(null);
    setAccessKey(null);
    setError(null);
  }

  // Authenticated — show DID + logout
  if (credential && accessKey) {
    return (
      <div className="mx-auto max-w-lg space-y-4 p-4">
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <h1 className="font-heading text-xl font-semibold">
              EffectStream Passkey Demo
            </h1>
            <p className="text-sm text-muted-foreground">
              Authenticated as {credential.credentialId.slice(0, 16)}...
            </p>
          </div>
          <Button variant="outline" onClick={handleLogout}>
            Logout
          </Button>
        </div>
        <DidStep accessKey={accessKey} />
      </div>
    );
  }

  // Not authenticated — register or sign in
  return (
    <div className="mx-auto max-w-lg space-y-4 p-4">
      <div className="space-y-1">
        <h1 className="font-heading text-xl font-semibold">
          EffectStream Passkey Demo
        </h1>
        <p className="text-sm text-muted-foreground">
          Proof of concept: passkey root key → access key → DID credential
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>
            {credential ? "Sign In" : "Get Started"}
          </CardTitle>
          <CardDescription>
            {credential
              ? "Authenticate with your passkey to access your DID credential."
              : "Register a new passkey or sign in with an existing one."}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {!credential && (
            <div className="space-y-1">
              <label htmlFor="username" className="text-xs text-muted-foreground">
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="flex h-8 w-full rounded-md border border-border bg-background px-3 py-1 text-sm"
              />
            </div>
          )}
          {error && <p className="text-xs text-destructive">{error}</p>}
          <div className="flex gap-2">
            {credential ? (
              <>
                <Button onClick={handleSignIn} disabled={loading}>
                  {loading ? "Authenticating..." : "Sign In with Passkey"}
                </Button>
                <Button variant="outline" onClick={handleLogout}>
                  Use a different account
                </Button>
              </>
            ) : (
              <>
                <Button onClick={handleRegister} disabled={loading || !username}>
                  {loading ? "Waiting..." : "Register"}
                </Button>
                <Button variant="outline" onClick={handleSignIn} disabled={loading}>
                  {loading ? "Waiting..." : "Sign In"}
                </Button>
              </>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
