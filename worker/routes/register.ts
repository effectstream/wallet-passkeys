import { Registration } from "webauthx/server";

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

export async function handleRegisterOptions(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = (await request.json()) as { username: string };
  const { challenge, options } = Registration.getOptions({
    name: body.username,
    rp: getRpConfig(request),
  });

  const sessionId = crypto.randomUUID();
  await env.CHALLENGES.put(
    sessionId,
    JSON.stringify({ challenge, username: body.username }),
    { expirationTtl: 300 },
  );

  return Response.json({ sessionId, options });
}

export async function handleRegisterVerify(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = (await request.json()) as {
    sessionId: string;
    credential: Registration.Credential;
  };

  const stored = await env.CHALLENGES.get(body.sessionId);
  if (!stored) {
    return Response.json({ error: "Challenge expired or not found" }, { status: 400 });
  }
  await env.CHALLENGES.delete(body.sessionId);

  const { challenge } = JSON.parse(stored) as { challenge: string; username: string };

  const result = Registration.verify(body.credential, {
    challenge: challenge as `0x${string}`,
    origin: getOrigin(request),
    rpId: getRpConfig(request).id,
    attestation: "none",
  });

  await env.CREDENTIALS.put(
    result.credential.id,
    JSON.stringify({
      id: result.credential.id,
      publicKey: result.credential.publicKey,
    }),
  );

  return Response.json({
    credentialId: result.credential.id,
    publicKey: result.credential.publicKey,
  });
}
