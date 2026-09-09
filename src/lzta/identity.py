"""Explicit reproduction assumption: RS256 JWT identity mapped to a CloudTrail ARN."""
from functools import lru_cache
from urllib.parse import urlparse


@lru_cache(maxsize=4)
def jwks_client(url):
    from jwt import PyJWKClient
    if urlparse(url).scheme != "https" or not urlparse(url).hostname:
        raise ValueError("JWKS URL must use HTTPS")
    return PyJWKClient(url, timeout=3)


def verify(token, issuer, audience, jwks_url):
    import jwt
    key = jwks_client(jwks_url).get_signing_key_from_jwt(token)
    claims = jwt.decode(token, key.key, algorithms=["RS256"], issuer=issuer,
                        audience=audience, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
    if not isinstance(claims["sub"], str) or not claims["sub"]:
        raise ValueError("Token subject is missing")
    return claims["sub"]
