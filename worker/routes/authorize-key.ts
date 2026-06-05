import { Authentication } from "webauthx/server";

function getRpConfig(request: Request) {
  const url = new URL(request.url);
  return {
    id: url.hostname,
    name: "EffectStream Passkeys",
  };
}

function getOrigin(request: Request) {
  const url = new URL(request.url);
  return url.origin;
}

/**
 * Step 1: Generate a challenge that commits to the access key's public key.
 * The passkey will sign this challenge, creating a key authorization.
 */
export async function handleAuthorizeKeyOptions(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = (await request.json()) as {
    credentialId: string;
    accessKeyPublicKey: string;
  };

  // The challenge embeds the access key public key so the passkey
  // signature is bound to this specific access key
  const challengePayload = JSON.stringify({
    action: "authorize-access-key",
    accessKeyPublicKey: body.accessKeyPublicKey,
    timestamp: Date.now(),
  });
  const challengeBytes = new TextEncoder().encode(challengePayload);
  const challengeHex = (
    "0x" +
    [...challengeBytes]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  ) as `0x${string}`;

  const { challenge, options } = Authentication.getOptions({
    credentialId: body.credentialId,
    rpId: getRpConfig(request).id,
    challenge: challengeHex,
  });

  const sessionId = crypto.randomUUID();
  await env.CHALLENGES.put(
    sessionId,
    JSON.stringify({
      challenge,
      credentialId: body.credentialId,
      accessKeyPublicKey: body.accessKeyPublicKey,
    }),
    { expirationTtl: 300 },
  );

  return Response.json({ sessionId, options });
}

/**
 * Step 2: Verify the passkey signed the challenge containing the access key,
 * then store the authorization.
 */
export async function handleAuthorizeKeyVerify(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = (await request.json()) as {
    sessionId: string;
    response: Authentication.Response & { id?: string };
  };

  const stored = await env.CHALLENGES.get(body.sessionId);
  if (!stored) {
    return Response.json(
      { error: "Challenge expired or not found" },
      { status: 400 },
    );
  }
  await env.CHALLENGES.delete(body.sessionId);

  const { challenge, credentialId, accessKeyPublicKey } = JSON.parse(
    stored,
  ) as {
    challenge: string;
    credentialId: string;
    accessKeyPublicKey: string;
  };

  const credentialData = await env.CREDENTIALS.get(credentialId);
  if (!credentialData) {
    return Response.json({ error: "Credential not found" }, { status: 404 });
  }

  const { publicKey: rootPublicKey } = JSON.parse(credentialData) as {
    id: string;
    publicKey: string;
  };

  const valid = Authentication.verify(body.response, {
    challenge: challenge as `0x${string}`,
    publicKey: rootPublicKey as `0x${string}`,
    origin: getOrigin(request),
    rpId: getRpConfig(request).id,
  });

  if (!valid) {
    return Response.json(
      { error: "Authorization signature invalid" },
      { status: 400 },
    );
  }

  // Store the key authorization: the passkey (root key) has cryptographically
  // authorized this access key to act on behalf of this account
  const authorization = {
    rootPublicKey,
    accessKeyPublicKey,
    credentialId,
    authorizedAt: Date.now(),
  };

  await env.CREDENTIALS.put(
    `auth:${credentialId}:${accessKeyPublicKey}`,
    JSON.stringify(authorization),
  );

  return Response.json({ authorized: true, authorization });
}
