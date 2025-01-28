import pytest

from pyeudiw.jwt.jws_helper import JWSHelper
from pyeudiw.jwt.utils import decode_jwt_header


class TestJWSHeperSelectSigningKey:
    @pytest.fixture
    def sign_jwks(self):
        return [
            {"crv":"P-256","d":"qIVMRJ0ioosFjCFhBw-kLBuip9tV0Y2D6iYD42nCKBA","kid":"ppBQZHPUTaEPdiLsj99gadhfqLtYMwiU9bmDCfAsWfI","kty":"EC","use":"sig","x":"_336mq5GanihcG_V40tiLDq2sFJ83w-vxaPAZtfCr40","y":"CYUM4Q1YlSTTgSp6OnJZt-O4YlzPf430AgVAM0oNlQk"},
            {"crv":"P-256","d":"SW976Rpuse5crOTbM5yBifa7u1tgw46XlJCJRwon4kA","kid":"35DgiI1eugPL1QB7sHG826YLLLLGDogvHmDa2jUilas","kty":"EC","use":"sig","x":"RXQ0lfXVXikgi00Yy8Qm2EX83_1JbLTXhyUXj9M21lk","y":"xTfCwP-eelZXMBFNKwiEUQaUJeebHWcVgnGyB7fOF1M"}
        ]

    def test_JWSHelper_select_signing_key_undefined(self, sign_jwks):
        signer = JWSHelper(sign_jwks)
        try:
            signer._select_signing_key(())
            assert False, "unable to select signing key when no header is given"
        except Exception:
            pass

    def test_JWSHelper_select_signing_key_forced(self, sign_jwks):
        signer = JWSHelper(sign_jwks)
        exp_k = sign_jwks[0]
        k = signer._select_signing_key(({}, {}), signing_kid=exp_k["kid"])
        assert k == exp_k

    def test_JWSHelper_select_signing_key_infer_kid(self, sign_jwks):
        signer = JWSHelper(sign_jwks)
        exp_k = sign_jwks[1]
        k = signer._select_signing_key(({"kid": exp_k["kid"]}, {}))
        assert k == exp_k

    def test_JWSHelper_select_signing_key_unique(self, sign_jwks):
        signer = JWSHelper(sign_jwks[0])
        exp_k = sign_jwks[0]
        k = signer._select_signing_key(({}, {}))
        assert k == exp_k


class TestJWSHelperSignerHeader():
    @pytest.fixture
    def sign_jwks(self):
        return [
            {"crv":"P-256","d":"qIVMRJ0ioosFjCFhBw-kLBuip9tV0Y2D6iYD42nCKBA","kid":"ppBQZHPUTaEPdiLsj99gadhfqLtYMwiU9bmDCfAsWfI","kty":"EC","use":"sig","x":"_336mq5GanihcG_V40tiLDq2sFJ83w-vxaPAZtfCr40","y":"CYUM4Q1YlSTTgSp6OnJZt-O4YlzPf430AgVAM0oNlQk"},
            {"crv":"P-256","d":"SW976Rpuse5crOTbM5yBifa7u1tgw46XlJCJRwon4kA","kid":"35DgiI1eugPL1QB7sHG826YLLLLGDogvHmDa2jUilas","kty":"EC","use":"sig","x":"RXQ0lfXVXikgi00Yy8Qm2EX83_1JbLTXhyUXj9M21lk","y":"xTfCwP-eelZXMBFNKwiEUQaUJeebHWcVgnGyB7fOF1M"}
        ]

    def test_signed_header_add_kid(self, sign_jwks):
        signer = JWSHelper(sign_jwks[0])
        jws = signer.sign("", protected={}, kid_in_header=True)
        dec_header = decode_jwt_header(jws)
        assert "kid" in dec_header
        assert sign_jwks[0]["kid"] == dec_header["kid"]

    def test_signed_header_no_add_kid(self, sign_jwks):
        signer = JWSHelper(sign_jwks[0])
        jws = signer.sign("", protected={}, kid_in_header=False)
        dec_header = decode_jwt_header(jws)
        assert not ("kid" in dec_header)

    def test_signed_header_add_alg(selg, sign_jwks):
        signer = JWSHelper(sign_jwks[0])
        jws = signer.sign("", protected={}, kid_in_header=False)
        dec_header = decode_jwt_header(jws)
        assert "alg" in dec_header


class TestJWSHelperSelectVerifyingKey():
    @pytest.fixture
    def verify_jwks(self):
        return [
            {"crv":"P-256","kid":"ppBQZHPUTaEPdiLsj99gadhfqLtYMwiU9bmDCfAsWfI","kty":"EC","use":"sig","x":"_336mq5GanihcG_V40tiLDq2sFJ83w-vxaPAZtfCr40","y":"CYUM4Q1YlSTTgSp6OnJZt-O4YlzPf430AgVAM0oNlQk"},
            {"crv":"P-256","kid":"35DgiI1eugPL1QB7sHG826YLLLLGDogvHmDa2jUilas","kty":"EC","use":"sig","x":"RXQ0lfXVXikgi00Yy8Qm2EX83_1JbLTXhyUXj9M21lk","y":"xTfCwP-eelZXMBFNKwiEUQaUJeebHWcVgnGyB7fOF1M"}
        ]

    def test_JWSHelper_select_verifying_key_undefined(self, verify_jwks):
        verifier = JWSHelper(verify_jwks)
        k = verifier._select_verifying_key({})
        assert k is None

    def test_JWSHelper_select_verifying_key_kid(self, verify_jwks):
        verifier = JWSHelper(verify_jwks)
        exp_k = verify_jwks[1]
        k = verifier._select_verifying_key({"kid": exp_k["kid"]})
        assert k == exp_k

    def test_JWSHelper_select_verifying_key_unique(self, verify_jwks):
        exp_k = verify_jwks[1]
        verifier = JWSHelper(exp_k)
        k = verifier._select_verifying_key({})
        assert k == exp_k


def test_verify_token_x5c_by_thumbprint():
    token = "eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCIsIng1YyI6WyJNSUlDNWpDQ0FtMmdBd0lCQWdJVU9LbkVIaFh3cmN3ZDY0cHV6WnlmQkprY3VJY3dDZ1lJS29aSXpqMEVBd0l3Z2FneE9EQTJCZ05WQkFNTUwwUldWaUJFYVdkcExVbEVJRTF2WTJzZ1FYUjBjbWxpZFhSbElGTmxZV3hwYm1jZ1EyVnlkR2xtYVdOaGRHVnpNU1l3SkFZRFZRUUtEQjFFYVdkcExTQnFZU0IydzZSbGMzVER0blJwWlhSdmRtbHlZWE4wYnpFUk1BOEdBMVVFQnd3SVNHVnNjMmx1YTJreEN6QUpCZ05WQkFZVEFrWkpNUkF3RGdZRFZRUUlEQWRHYVc1c1lXNWtNUkl3RUFZRFZRUUZFd2t3TWpRMU5ETTNMVEl3SGhjTk1qUXdOVEUyTURnME56STNXaGNOTWpVd05URTJNRGcwTnpJM1dqQ0JwekUzTURVR0ExVUVBd3d1UkZaV0lFUnBaMmt0U1VRZ1RXOWpheUJCZEhSeWFXSjFkR1VnVTJWaGJHbHVaeUJEWlhKMGFXWnBZMkYwWlRFbU1DUUdBMVVFQ2d3ZFJHbG5hUzBnYW1FZ2RzT2taWE4wdzdaMGFXVjBiM1pwY21GemRHOHhFVEFQQmdOVkJBY01DRWhsYkhOcGJtdHBNUXN3Q1FZRFZRUUdFd0pHU1RFUU1BNEdBMVVFQ0F3SFJtbHViR0Z1WkRFU01CQUdBMVVFQlJNSk1ESTBOVFF6TnkweU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRVdTaWluVE5RWXFZZWwvS0tnYjRzVXZJQTVCZ0Zmdyt1ckpaRW1RaEJablZweitTZ1hoa2hrNk9NZ0Z6Y0hBUWZDYzBIcDhSRWc2NkJIZnM2VUtKbzJxTjBNSEl3RHdZRFZSMFRBUUgvQkFVd0F3SUJBREFPQmdOVkhROEJBZjhFQkFNQ0I0QXdGUVlEVlIwbEFRSC9CQXN3Q1FZSEtJR01YUVVCQWpBWkJnTlZIUklFRWpBUWhnNW9kSFJ3Y3pvdkwyUjJkaTVtYVRBZEJnTlZIUkVFRmpBVWdoSnhZUzVwWkM1amJHOTFaQzVrZG5ZdVpta3dDZ1lJS29aSXpqMEVBd0lEWndBd1pBSXdCemx5Q3RVL090aVpYOU94Tit1YWlFbUgybTgrY21sRTA0dzgyem9JRE0wbXRuK01TSGhIV0w2TEZybXpOMmFYQWpCczNIY1ZwQncySnNpTmJ3TFY5RXUzTHNha2hBQlA0SnlpejlydngyZXJMQUNuRUpPVzBCNGsyWkpvR0hmWnBWUT0iXX0.eyJfc2QiOlsiNy1GQjZxeWZPV2d5NS1ZcHZpYnRvRWdhUWtoOF9YV19fUHBqcVRtN2xLTSIsIklHMWRDbkpiMXJVeWJQeklONkotQkNDLWdfUF9PT3pxR3JvblE1Y0ltSFkiLCJDVllxUXgweU5QZ0ptMXAtdTNkR3BZQnFhSE82dkZGWTA0WVo1Rk1tVXNvIiwiLW8tOExfY0NqRmpjX2YteU9JTTJuMnB1STlmQmpIbHlFclp2SHZhVDRidyIsImc3SUVNSGlhNFdURUxsQmxSQ3JlOFFyWjBrYTJ1MFo5SjFNbzlJM3dUV28iLCJmeXZhdFBHa3BhdW15TVZ2Wm9vRFR3V2JDRnYwdFB0VFNIZWVfeXNsVHZFIiwiYVBXTnJzeE8wR25WVGI5RGhMSHdmOUJ6MG9CWEVldlIwS09fN3JFSmk1RSIsIlVlM3NSR1h6NjNoc2wzNnl6VzhGdXdnc1lKdEJvTDJ6MVlyQnhPczlwZkEiLCJSOEZPZWUzRUhCVGNNTjlhZWhzVndrZWdGVzZXUUJKWGVndW10V0tGM3NrIiwicFVuNFNiUEJXajAxWXVkbWV1WThZN2pfeEZyRno0T2pLRWtqVXdlT0huSSIsIlg0VGstS0FiMHljU0QzMF92YlVodTMzY1pnNHNic1pweXdDeGNLNHBXcnMiLCJWbEw1NnlGYkFNUFI1bVhKTXNmNmxCMTZhUURJVDZ4eElENThad0k5cV9FIl0sIm5iZiI6MTczNzk3NzQ5NCwiX3NkX2FsZyI6InNoYS0yNTYiLCJ2Y3QiOiJ1cm46ZXUuZXVyb3BhLmVjLmV1ZGk6cGlkOjEiLCJpc3MiOiJodHRwczovL3FhLmlkLmNsb3VkLmR2di5maS9waWQtcHJvdmlkZXIvcGlkLzEuMCIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJHcFN6YW9rdUl2T0xQa2ZKSUlwajJxaDItVE5JS2hzaTk5RnRoMF9hcnJvIiwieSI6IlJZOGQ3ckZVV21ibmJldmxvY0tBYTNuRFozcGJ5cWhBVUtVWEZNVTcwRnMifX0sImV4cCI6MTc0NTc1MzQ5NCwiaWF0IjoxNzM3OTc3NDk0LCJzdGF0dXMiOnsic3RhdHVzX2xpc3QiOnsidXJpIjoiaHR0cHM6Ly9xYS5pZC5jbG91ZC5kdnYuZmkvc3RhdHVzLWxpc3QtdG9rZW4vODExYjhmZDctMzE4YS00YzUxLTgyMjQtNjhmZTE2ZDY5MzRiIiwiaWR4IjozODU5MzZ9fX0.K5g7oOTcZngpFNTYe7Hg4nvEn0TTQPh40fe4fBcjNQ1GpqoqBHmo8Xai37NnxK-tdNNxbHEI99UUcOlRXXUP3Q"
    keys = [
        {
            "kty": "EC",
            "use": "sig",
            "crv": "P-256",
            "kid": "323489393350363785490670228924001503025813043335",
            "x": "WSiinTNQYqYel_KKgb4sUvIA5BgFfw-urJZEmQhBZnU",
            "y": "ac_koF4ZIZOjjIBc3BwEHwnNB6fERIOugR37OlCiaNo"
        }
    ]
    verifier = JWSHelper(keys)
    verifier.verify(token)
