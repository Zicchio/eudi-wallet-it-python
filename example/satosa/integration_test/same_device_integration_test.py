import json
import requests
import urllib
import base64
from bs4 import BeautifulSoup

from commons import (
    INITIATING_SAML_REQUEST_URI,
    ISSUER_CONF,
    apply_trust_settings,
    create_authorize_response,
    create_holder_test_data,
    create_issuer_test_data,
    setup_test_db_engine
)

from pyeudiw.jwt.utils import decode_jwt_payload

from settings import (
    TIMEOUT_S,
)

db_engine_inst = setup_test_db_engine()
db_engine_inst = apply_trust_settings(db_engine_inst)

headers_mobile = {
    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B137 Safari/601.1'
}
# initialize the user-agent
http_user_agent = requests.Session()


request_uri = ''
try:
    authn_response = http_user_agent.get(
        url=INITIATING_SAML_REQUEST_URI,
        verify=False,
        headers=headers_mobile,
        timeout=TIMEOUT_S
    )
except requests.exceptions.InvalidSchema as e:
    request_uri = urllib.parse.unquote_plus(
        e.args[0].split("request_uri="
                        )[1][:-1]
    )


sign_request_obj = http_user_agent.get(
    request_uri,
    verify=False,
    timeout=TIMEOUT_S)

request_object_claims = decode_jwt_payload(sign_request_obj.text)
response_uri = request_object_claims['response_uri']

# Provide an authentication response
verifiable_credential = create_issuer_test_data()
verifiable_presentations = create_holder_test_data(
    verifiable_credential,
    request_object_claims['nonce']
)
wallet_response_data = create_authorize_response(
    verifiable_presentations,
    request_object_claims["state"],
    request_object_claims["nonce"],
    response_uri
)

authz_response_ok = http_user_agent.post(
    response_uri,
    verify=False,
    data={'response': wallet_response_data},
    timeout=TIMEOUT_S
)

assert 'redirect_uri' in authz_response_ok.content.decode()
callback_uri = json.loads(authz_response_ok.content.decode())['redirect_uri']
satosa_authn_response = http_user_agent.get(
    callback_uri,
    verify=False,
    timeout=TIMEOUT_S
)

assert 'SAMLResponse' in satosa_authn_response.content.decode()
print(satosa_authn_response.content.decode())

soup = BeautifulSoup(satosa_authn_response.content.decode(), features="lxml")
form = soup.find("form")
assert "/saml2" in form["action"]
input_tag = soup.find("input")
assert input_tag["name"] == "SAMLResponse"

lowered = base64.b64decode(input_tag["value"]).lower()
value = BeautifulSoup(lowered, features="xml")
attributes = value.find_all("saml:attribute")
# expect to have a non-empty list of attributes
assert attributes

expected = {
    # https://oidref.com/2.5.4.42
    "urn:oid:2.5.4.42": ISSUER_CONF['sd_specification'].split('!sd given_name:')[1].split('"')[1],
    # https://oidref.com/2.5.4.4
    "urn:oid:2.5.4.4": ISSUER_CONF['sd_specification'].split('!sd family_name:')[1].split('"')[1]
}

for attribute in attributes:
    name = attribute["name"]
    value = attribute.contents[0].contents[0]
    expected_value = expected.get(name, None)
    if expected_value:
        assert value == expected_value.lower()

print('TEST PASSED')