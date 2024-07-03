import type { APIRoute } from 'astro';
import { WorkOS } from "@workos-inc/node";
import { sealData } from 'iron-session';

const workos = new WorkOS(import.meta.env.WORKOS_API_KEY);
const clientId = import.meta.env.WORKOS_CLIENT_ID;

export const GET: APIRoute = async ({ redirect, request, cookies }) => {
  // The authorization code returned by AuthKit
  // This is the URL, http://localhost:4321/api/callback?code=01J003J73R07HSP5CFWBE33PEP
  const code = new URL(request.url).searchParams.get('code') as string;

  const { user, accessToken, refreshToken, impersonator } = await workos.userManagement.authenticateWithCode({
    code,
    clientId,
  });

  // The refreshToken should never be accessible publicly,
  // hence why we encrypt it in the cookie session.
  // Alternatively you could persist the refresh token in a backend database
  const encryptedSession = await sealData(
    { accessToken, refreshToken, user, impersonator },
    { password: import.meta.env.WORKOS_COOKIE_PASSWORD },
  );

  // Store the session in a cookie
  cookies.set('wos-session', encryptedSession, {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
  });

  // Use the information in `user` for further business logic.

  // Redirect the user to the homepage
  return redirect("/admin/dashboard", 302);
};
