import { unsealData } from "iron-session";

export const getUser = (cookies) => {
  if (cookies.get('wos-session')) {
    return unsealData(cookies.get('wos-session').value, {
      password: import.meta.env.WORKOS_COOKIE_PASSWORD,
    });
  } else {
    console.log('user is unauthenticated');
    return null;
  }
}