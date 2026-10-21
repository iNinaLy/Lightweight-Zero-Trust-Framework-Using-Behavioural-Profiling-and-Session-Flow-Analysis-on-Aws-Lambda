"""Interactive browser sign-in and API check; credentials stay in memory."""
import argparse
import base64
import getpass
import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
import webbrowser


def callback_code(url, redirect_uri, state):
    callback = urllib.parse.urlsplit(url.strip())
    expected = urllib.parse.urlsplit(redirect_uri)
    # Browsers serialize an empty root path as '/'. Keep all other paths exact.
    if (callback.scheme, callback.netloc, callback.path or '/') != (
        expected.scheme, expected.netloc, expected.path or '/'
    ) or callback.fragment:
        raise ValueError('Expected the final https://localhost/?code=...&state=... URL. '
                         'Copy the address after sign-in, not the Cognito sign-in address.')
    query = urllib.parse.parse_qs(callback.query)
    if 'error' in query:
        # Never echo provider-controlled text or the callback's code/state.
        raise ValueError('Cognito returned a sign-in error instead of an authorization code. '
                         'Complete sign-in using the browser tab opened by this running helper.')
    if not query.get('state'):
        raise ValueError('The pasted URL has no state parameter. Copy the entire address, '
                         'including everything after &state=.')
    if query.get('state') != [state]:
        raise ValueError('This URL belongs to a different sign-in attempt. Use the browser tab '
                         'opened by this running helper, not an earlier tab or redirect.')
    if len(query.get('code', [])) != 1:
        raise ValueError('The pasted URL has no single authorization code. Finish sign-in '
                         'and copy the complete final localhost address.')
    return query['code'][0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain', required=True, help='Cognito hosted-login hostname')
    parser.add_argument('--client-id', required=True)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--redirect-uri', default='https://localhost')
    parser.add_argument('--user-agent', default='lzta-auth-check/1.0')
    parser.add_argument('--check-changed-agent', action='store_true',
                        help='Also test a different User-Agent with the same token')
    args = parser.parse_args()
    if urllib.parse.urlsplit(args.endpoint).scheme != 'https':
        parser.error('API endpoint must use HTTPS')
    if '/' in args.domain or not args.domain.endswith('.amazoncognito.com'):
        parser.error('Supply a Cognito hosted-login hostname without a scheme or path')
    verifier = secrets.token_urlsafe(48)
    state = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    login_url = 'https://' + args.domain + '/oauth2/authorize?' + urllib.parse.urlencode({
        'client_id': args.client_id, 'response_type': 'code',
        'redirect_uri': args.redirect_uri, 'scope': 'openid', 'state': state,
        'code_challenge': challenge, 'code_challenge_method': 'S256',
    })
    print('Opening Cognito sign-in in your browser.')
    print('After sign-in, localhost may show a connection error. Copy the full address bar URL.')
    print('Paste it at the hidden prompt here, never into chat. No token will be saved or printed.')
    if not webbrowser.open(login_url):
        print('Open this sign-in URL locally:', login_url)
    while True:
        try:
            code = callback_code(getpass.getpass('Redirect URL (hidden; Ctrl+C to cancel): '),
                                 args.redirect_uri, state)
            break
        except ValueError as error:
            print(error)
            print('This helper is still waiting. Paste the corrected URL here.')
    request = urllib.request.Request('https://' + args.domain + '/oauth2/token', data=urllib.parse.urlencode({
        'grant_type': 'authorization_code', 'client_id': args.client_id,
        'redirect_uri': args.redirect_uri, 'code': code, 'code_verifier': verifier,
    }).encode(), headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            tokens = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f'Cognito token exchange failed: HTTP {error.code}') from None
    print('Cognito token exchange succeeded. Testing the protected endpoint.')
    probes = [('Matching context', args.user_agent, 200)]
    if args.check_changed_agent:
        probes.append(('Changed User-Agent', args.user_agent + '-unrecognized', 403))
    results = []
    for label, agent, expected_status in probes:
        request = urllib.request.Request(args.endpoint, headers={
            'Authorization': 'Bearer ' + tokens['id_token'], 'User-Agent': agent,
        })
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                status, headers = response.status, response.headers
        except urllib.error.HTTPError as error:
            status, headers = error.code, error.headers
            error.close()
        print(label + ' API HTTP status:', status)
        print('API request ID:', headers.get('x-amzn-requestid') or headers.get('x-amz-apigw-id') or 'unavailable')
        results.append(status == expected_status)
    if args.check_changed_agent and not all(results):
        raise RuntimeError('Expected matching context HTTP 200 and changed User-Agent HTTP 403. Check authorizer logs.')


if __name__ == '__main__':
    main()
