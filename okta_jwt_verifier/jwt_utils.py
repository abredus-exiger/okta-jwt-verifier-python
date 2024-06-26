import base64
import json

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import ExpiredSignatureError

from .constants import LEEWAY
from .exceptions import JWTValidationException

jws = jwt.PyJWS()


class JWTUtils:
    """Contains different utils and common methods for jwt verification."""

    @staticmethod
    def parse_token(token):
        """Parse JWT token, get headers, claims and signature.

        Return:
            tuple (headers, claims, signing_input, signature)
        """
        payload, signing_input, header, signature = jws._load(token)
        claims = json.loads(payload.decode('utf-8'))
        return header, claims, signing_input, signature

    @staticmethod
    def verify_claims(claims,
                      claims_to_verify,
                      audience,
                      issuer,
                      leeway=LEEWAY):
        """Verify claims are present and valid."""
        # Check if required claims are present, because library "jose" doesn't raise an exception
        for claim in claims_to_verify:
            if claim not in claims:
                raise JWTValidationException(f'Required claim "{claim}" is not present.')

        # Overwrite defaults in python-jose library
        options = {'verify_aud': 'aud' in claims_to_verify,
                   'verify_iat': 'iat' in claims_to_verify,
                   'verify_exp': 'exp' in claims_to_verify,
                   'verify_nbf': 'nbf' in claims_to_verify,
                   'verify_iss': 'iss' in claims_to_verify,
                   'verify_sub': 'sub' in claims_to_verify,
                   'verify_jti': 'jti' in claims_to_verify,
                   'leeway': leeway,
                   'require': claims_to_verify}
        # Validate claims

        jwt.PyJWT()._validate_claims(payload=claims,
                                     audience=audience,
                                     issuer=issuer,
                                     options=options)

    @staticmethod
    def verify_signature(token, okta_jwk):
        """Verify token signature using received jwk."""

        def base64url_decode(code: str) -> bytes:
            padding = "=" * (4 - (len(code) % 4))
            return base64.urlsafe_b64decode(code + padding)

        headers, _, signing_input, signature = JWTUtils.parse_token(token)
        # !FIXME This is purely for testing purposes
        if isinstance(okta_jwk, str):
            key = okta_jwk
        else:
            # pyjwt expects the key in PEM format
            n = int.from_bytes(base64url_decode(okta_jwk["n"]), byteorder="big")
            e = int.from_bytes(base64url_decode(okta_jwk["e"]), byteorder="big")
            key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
        jws._verify_signature(signing_input=signing_input,
                              header=headers,
                              signature=signature,
                              key=key,
                              algorithms=['RS256'])

    @staticmethod
    def verify_expiration(token, leeway=LEEWAY):
        """Verify if token is not expired."""
        headers, claims, signing_input, signature = JWTUtils.parse_token(token)
        try:
            JWTUtils.verify_claims(claims,
                                   claims_to_verify=('exp',),
                                   audience=None,
                                   issuer=None,
                                   leeway=LEEWAY)
        except ExpiredSignatureError:
            raise JWTValidationException('Signature has expired.')
