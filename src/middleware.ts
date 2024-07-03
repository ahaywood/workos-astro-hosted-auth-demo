// Javascript Object Signing and Encryption (JOSE)
// https://www.npmjs.com/package/jose
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { WorkOS } from "@workos-inc/node";
import { sealData, unsealData } from 'iron-session';

import { sequence } from "astro:middleware";

const workos = new WorkOS(import.meta.env.WORKOS_API_KEY);
const clientId = import.meta.env.WORKOS_CLIENT_ID;

// Set the JWKS URL. This is used to verify if the JWT is still valid
const JWKS = createRemoteJWKSet(
  new URL(workos.userManagement.getJwksUrl(clientId)),
);

// Auth middleware function
async function withAuth(context, next) {
  const { cookies, redirect, req, res } = context;

  // First, attempt to get the session from the cookie
  const session = await getSessionFromCookie(cookies);

  // If no session, redirect the user to the login page
  if (!session) {
    return redirect('/auth');
  }

  const hasValidSession = await verifyAccessToken(session.accessToken);

  // If the session is valid, move on to the next function
  if (hasValidSession) {
    return next();
  }

  try {
    // If the session is invalid (i.e. the access token has expired)
    // attempt to re-authenticate with the refresh token
    const { accessToken, refreshToken } =
      await workos.userManagement.authenticateWithRefreshToken({
        clientId,
        refreshToken: session.refreshToken,
      });

    // Refresh tokens are single use, so update the session with the
    // new access and refresh tokens
    const encryptedSession = await sealData(
      {
        accessToken,
        refreshToken,
        user: session.user,
        impersonator: session.impersonator,
      },
      { password: import.meta.env.WORKOS_COOKIE_PASSWORD },
    );

    // Update the cookie
    cookies.set('wos-session', encryptedSession, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
    });

    return next();
  } catch (e) {
    // Failed to refresh access token, redirect user to login page
    // after deleting the cookie
    cookies.delete('wos-session');
    redirect('/auth');
  }
}

async function getSessionFromCookie(cookies) {
  const cookie = cookies.get('wos-session');

  if (cookie) {
    return unsealData(cookie.value, {
      password: import.meta.env.WORKOS_COOKIE_PASSWORD,
    });
  }
}

async function verifyAccessToken(accessToken) {
  try {
    await jwtVerify(accessToken, JWKS);
    return true;
  } catch (e) {
    console.warn('Failed to verify session:', e);
    return false;
  }
}

// export const onRequest = sequence(withAuth);
export async function onRequest(context, next) {
  if (context.url.pathname.startsWith("/admin/")) {
    return await withAuth(context, next);
  } else {
    // return a Response or the result of calling `next()`
    return next();
  }

};