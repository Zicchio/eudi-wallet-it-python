import cryptojwt
import cryptojwt.jwk
from cryptojwt.jwk.ec import import_ec_key, ECKey
from cryptojwt.jwk.rsa import import_rsa_key, RSAKey

from pyeudiw.jwk import JWK
from pyeudiw.jwk.exceptions import InvalidJwk


def adapt_key_to_JWK(key: dict | JWK | cryptojwt.jwk.JWK) -> JWK:
    """Function adapt_key_to_JWK normalize key representation format to
    the internal JWK.
    """
    if isinstance(key, JWK):
        return key
    if isinstance(key, dict):
        return JWK(key)
    if isinstance(key, cryptojwt.jwk.JWK):
        return JWK(key.to_dict())
    raise ValueError(f"not a valid or supported key format: {type(key)}")


def parse_key_from_x5c(x5c: list[str]) -> JWK:
    """Parse a key from an x509 chain. This function currently
    support only the parsing of public RSA and EC key from such a chain.
    The first element of the chain will contain the verifying key.
    See RFC7517 https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
    """
    try:
        # maybe RSA?
        public_key = import_rsa_key(x5c[0])
        key_dict = RSAKey(pub_key=public_key).to_dict()
        return JWK(key_dict)
    except Exception:
        # maybe EC?
        public_key = import_ec_key(x5c[0])
        key_dict = ECKey(pub_key=public_key).to_dict()
        return JWK(key_dict)
    except Exception:
        # neither RSA nor EC
        raise InvalidJwk(f"unable to parse key from x5c: {x5c}")
