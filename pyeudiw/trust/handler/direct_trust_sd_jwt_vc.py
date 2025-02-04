import os
from urllib.parse import urlparse

from pyeudiw.trust.handler._direct_trust_jwk import _DirectTrustJwkHandler
from pyeudiw.trust.handler.exception import InvalidJwkMetadataException
from pyeudiw.trust.model.trust_source import TrustSourceData
from pyeudiw.tools.utils import cacheable_get_http_url, get_http_url


DEFAULT_SDJWTVC_METADATA_ENDPOINT = "/.well-known/jwt-vc-issuer"
"""Default endpoint where issuer keys used for sd-jwt vc are exposed.
For further reference, see https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-06.html#name-jwt-vc-issuer-metadata
"""

DEFAULT_OPENID4VCI_METADATA_ENDPOINT = "/.well-known/openid-credential-issuer"
"""Default endpoint where metadata issuer credential are exposed/
For further reference, see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-well-known-uri-registry
"""

DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS = {
    "connection": {
        "ssl": os.getenv("PYEUDIW_HTTPC_SSL", True)
    },
    "session": {
        "timeout": os.getenv("PYEUDIW_HTTPC_TIMEOUT", 6)
    }
}


class DirectTrustSdJwtVc(_DirectTrustJwkHandler):
    """DirectTrustSdJwtVc is specialization of _DirectTrustJwkHandler
    used in the context of sd-jwt for verifiable credentials.
    """

    def __init__(
        self,
        httpc_params: dict = DEFAULT_DIRECT_TRUST_SD_JWC_VC_PARAMS,
        jwk_endpoint: str = DEFAULT_SDJWTVC_METADATA_ENDPOINT,
        metadata_endpoint: str = DEFAULT_OPENID4VCI_METADATA_ENDPOINT,
        cache_ttl: int = 0,
        jwks: list[dict] | None = None
    ):
        super().__init__(
            httpc_params=httpc_params,
            jwk_endpoint=jwk_endpoint,
            cache_ttl=cache_ttl,
            jwks=jwks
        )
        self.metadata_endpoint = metadata_endpoint

    def _get_jwk_metadata(self, issuer_id: str) -> dict:
        error_list: list[Exception] = []
        if not self.jwk_endpoint:
            return {}
        # first look for the correct endpoint
        try:
            endpoint = build_jwk_issuer_endpoint_ietf_way(issuer_id, self.jwk_endpoint)
            if self.cache_ttl:
                resp = cacheable_get_http_url(
                    self.cache_ttl, endpoint, self.httpc_params, http_async=self.http_async_calls)
            else:
                resp = get_http_url([endpoint], self.httpc_params, http_async=self.http_async_calls)[0]
            if (not resp) or (resp.status_code != 200):
                raise InvalidJwkMetadataException(
                    f"failed to fetch valid jwk metadata (searched in {endpoint}): obtained {resp}")
            return resp.json()
        except Exception as e_ietf:
            error_list.append(e_ietf)

        # then, look for the wrong endpoint
        try:
            endpoint = build_jwk_issuer_endpoint_openid_way(issuer_id, self.jwk_endpoint)
            resp = get_http_url([endpoint], self.httpc_params, http_async=self.http_async_calls)[0]
            if (not resp) or (resp.status_code != 200):
                raise InvalidJwkMetadataException(
                    f"failed to fetch valid jwk metadata (searched in {endpoint}): obtained {resp}")
            return resp.json()
        except Exception as e_openid:
            error_list.append(e_openid)

        raise InvalidJwkMetadataException(f"failed to find jwk metadata: obtained exception: {error_list}")

    def get_metadata(self, issuer: str, trust_source: TrustSourceData) -> TrustSourceData:
        """
        Fetches the public metadata of an issuer by interrogating a given
        endpoint. The endpoint must yield information in a format that
        can be transalted to a meaning dictionary (such as json)

        :returns: a dictionary of metadata information
        """
        url = build_metadata_issuer_endpoint(issuer, self.metadata_endpoint)
        if self.cache_ttl == 0:
            trust_source.metadata = get_http_url(url, self.httpc_params, self.http_async_calls)[0].json()
        else:
            trust_source.metadata = cacheable_get_http_url(self.cache_ttl, url, self.httpc_params, self.http_async_calls).json()

        return trust_source


def build_metadata_issuer_endpoint(issuer_id: str, endpoint_component: str) -> str:
    return issuer_id.rstrip('/') + '/' + endpoint_component.lstrip('/')


def build_jwk_issuer_endpoint_ietf_way(issuer_id: str, endpoint_component: str) -> str:
    if not endpoint_component:
        return issuer_id
    baseurl = urlparse(issuer_id)
    full_endpoint_path = '/' + endpoint_component.strip('/') + baseurl.path
    return baseurl._replace(path=full_endpoint_path).geturl()


def build_jwk_issuer_endpoint_openid_way(issuer_id: str, endpoint_component: str) -> str:
    if not endpoint_component:
        return issuer_id
    return issuer_id.rstrip('/') + '/' + endpoint_component.lstrip('/')
