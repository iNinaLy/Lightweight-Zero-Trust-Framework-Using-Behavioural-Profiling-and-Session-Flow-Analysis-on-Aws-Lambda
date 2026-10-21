const encode = (data) => btoa(String.fromCharCode(...data)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
function decodeClaims(token) {
  const part = token.split('.')[1].replaceAll('-', '+').replaceAll('_', '/');
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(part.padEnd(Math.ceil(part.length / 4) * 4, '=')), (character) => character.charCodeAt(0))));
}
export async function signIn(config) {
  const verifier = encode(crypto.getRandomValues(new Uint8Array(48)));
  const state = encode(crypto.getRandomValues(new Uint8Array(32)));
  const nonce = encode(crypto.getRandomValues(new Uint8Array(32)));
  sessionStorage.setItem('lzta.oauth', JSON.stringify({verifier, state, nonce, started: Date.now()}));
  const challenge = encode(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
  const query = new URLSearchParams({client_id: config.clientId, response_type: 'code', redirect_uri: config.redirectUri,
    scope: 'openid email', state, nonce, code_challenge: challenge, code_challenge_method: 'S256'});
  location.assign(`https://${config.cognitoDomain}/oauth2/authorize?${query}`);
}
export function signOut(config) {
  sessionStorage.removeItem('lzta.session'); sessionStorage.removeItem('lzta.oauth');
  const query = new URLSearchParams({client_id: config.clientId, logout_uri: config.redirectUri});
  location.assign(`https://${config.cognitoDomain}/logout?${query}`);
}
export async function resumeSignIn(config) {
  const query = new URLSearchParams(location.search);
  if (query.has('code') || query.has('error')) {
    history.replaceState(null, '', location.pathname);
    const pending = JSON.parse(sessionStorage.getItem('lzta.oauth') || 'null');
    sessionStorage.removeItem('lzta.oauth');
    if (query.has('error')) throw new Error('Sign-in was not completed. Please try again.');
    if (!pending || query.get('state') !== pending.state || Date.now() - pending.started > 15 * 60 * 1000) {
      throw new Error('This sign-in attempt expired or belongs to another tab. Please sign in again.');
    }
    const response = await fetch(`https://${config.cognitoDomain}/oauth2/token`, {
      method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: new URLSearchParams({grant_type: 'authorization_code', client_id: config.clientId,
        redirect_uri: config.redirectUri, code: query.get('code'), code_verifier: pending.verifier}), signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) throw new Error('Could not complete sign-in. Please start a new sign-in attempt.');
    const tokens = await response.json();
    const identity = decodeClaims(tokens.id_token);
    if (identity.nonce !== pending.nonce || identity.aud !== config.clientId || identity.iss !== config.issuer
      || identity.token_use !== 'id' || identity.exp * 1000 <= Date.now()) throw new Error('The sign-in response was invalid. Please sign in again.');
    // AWS independently verifies the token signature and identity on every API request.
    sessionStorage.setItem('lzta.session', JSON.stringify({idToken: tokens.id_token, expires: identity.exp * 1000}));
  }
  const saved = JSON.parse(sessionStorage.getItem('lzta.session') || 'null');
  if (saved?.expires > Date.now() + 15000) return saved.idToken;
  sessionStorage.removeItem('lzta.session');
  return null;
}
