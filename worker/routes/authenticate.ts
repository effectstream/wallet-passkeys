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

export async function handleAuthOptions(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = (await request.json()) as { credentialId?: string };

  // Support discoverable credentials (no credentialId) for sign-in
  const opts: Record<string, unknown> = {
    rpId: getRpConfig(request).id,
  };
  if (body.credentialId) {
    opts.credentialId = body.credentialId;
  }

  const { challenge, options } = Authentication.getOptions(opts as never);

  const sessionId = crypto.randomUUID();
  await env.CHALLENGES.put(
    sessionId,
    JSON.stringify({ challenge, credentialId: body.credentialId ?? null }),
    { expirationTtl: 300 },
  );

  return Response.json({ sessionId, options });
}

export async function handleAuthVerify(
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

  const { challenge, credentialId: storedCredentialId } = JSON.parse(
    stored,
  ) as {
    challenge: string;
    credentialId: string | null;
  };

  // Use the credential ID from the authentication response (discoverable)
  // or fall back to the one stored with the challenge
  const credentialId = body.response.id ?? storedCredentialId;
  if (!credentialId) {
    return Response.json(
      { error: "No credential ID in response" },
      { status: 400 },
    );
  }

  const credentialData = await env.CREDENTIALS.get(credentialId);
  if (!credentialData) {
    return Response.json({ error: "Credential not found" }, { status: 404 });
  }

  const { publicKey } = JSON.parse(credentialData) as {
    id: string;
    publicKey: string;
  };

  const valid = Authentication.verify(body.response, {
    challenge: challenge as `0x${string}`,
    publicKey: publicKey as `0x${string}`,
    origin: getOrigin(request),
    rpId: getRpConfig(request).id,
  });

  return Response.json({ valid, credentialId, publicKey });
}
