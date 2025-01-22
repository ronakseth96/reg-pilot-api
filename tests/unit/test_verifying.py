import fastapi
from starlette.datastructures import Headers

from regps.app.api.exceptions import DigestVerificationFailedException
from regps.app.api import signed_headers_verifier
import pytest
from hashlib import sha256
from regps.app.api.digest_verifier import verify_digest


def test_digest_verification():
    BASE_STR = "fefUBIUhdo9032bfHf0UNONF0kubni9HnF22L0KD2".encode()
    dig = sha256(BASE_STR).hexdigest()
    dig = f"sha256-{dig}"
    assert verify_digest(BASE_STR, dig) is True


def test_digest_verification_fail():
    BASE_STR = "fefUBIUhdo9032bfHf0UNONF0kubni9HnF22L0KD2".encode()
    WRONG_BASE_STR = "fefUBIUhdo9032bfHf0UNONF0kubni9HnF22L0KDT".encode()
    dig = sha256(BASE_STR).hexdigest()
    dig = f"sha256-{dig}"
    assert verify_digest(WRONG_BASE_STR, dig) is False


def test_digest_verification_wrong_dig():
    BASE_STR = "fefUBIUhdo9032bfHf0UNONF0kubni9HnF22L0KD2".encode()
    dig = sha256(BASE_STR).hexdigest()
    # Here the dig is not prefixed
    with pytest.raises(DigestVerificationFailedException):
        verify_digest(BASE_STR, dig)


def test_verify_cig():
    # AID and SAID should be the same as what is in credential.cesr for the ECR credential
    # see https://trustoverip.github.io/tswg-acdc-specification/#top-level-fields to understand the fields/values
    AID = "EC3Rm0f9aQiZz2hxZOIup5Soyu6x_aA5996LP-eN6hBu"
    # SAID = "EHw8lEt5PmJZa-_eFdjxBNNUw4f8l3pT5lAZAQNc__SI"

    headers = {
        "HOST": "localhost:7676",
        "CONNECTION": "keep-alive",
        "METHOD": "POST",
        "SIGNATURE": 'indexed="?0";signify="0BAo0wmWUJRG6a_-kmdeYWRhVdjifc9Dp7cEWxpFpLp4fUf114pb7Qec3r43uqGWfQdu33ci5PTDFgcIiDjsDPMI"',
        "SIGNATURE-INPUT": 'signify=("@method" "@path" "signify-resource" "signify-timestamp");created=1737497943;keyid="BAIGwtGP4CFwVqXiU9bspN5_eoWpPfNh9qChkK6FtDAu";alg="ed25519"',
        "SIGNIFY-RESOURCE": 'EC3Rm0f9aQiZz2hxZOIup5Soyu6x_aA5996LP-eN6hBu',
        "SIGNIFY-TIMESTAMP": "2025-01-21T22:19:03.646000+00:00",
        "ACCEPT": "*/*",
        "ACCEPT-LANGUAGE": "*",
        "SEC-FETCH-MODE": "cors",
        "USER-AGENT": "node",
        "ACCEPT-ENCODING": "gzip, deflate",
    }
    scope = dict(type="http", headers=Headers(headers).raw, method="POST", path="/")
    req = fastapi.Request(scope)
    aid, sig, ser = signed_headers_verifier.VerifySignedHeaders.handle_headers(req)
    assert aid == AID
    assert (
        sig
        == "0BAo0wmWUJRG6a_-kmdeYWRhVdjifc9Dp7cEWxpFpLp4fUf114pb7Qec3r43uqGWfQdu33ci5PTDFgcIiDjsDPMI"
    )

def test_verify_forwarded_cig():
    # AID and SAID should be the same as what is in credential.cesr for the ECR credential
    # see https://trustoverip.github.io/tswg-acdc-specification/#top-level-fields to understand the fields/values
    AID = "EC3Rm0f9aQiZz2hxZOIup5Soyu6x_aA5996LP-eN6hBu"
    # SAID = "EElnd1DKvcDzzh7u7jBjsg2X9WgdQQuhgiu80i2VR-gk"

    # See https://datatracker.ietf.org/doc/html/rfc9421#section-4.3 for forwarding signed headers
    headers = {
        "HOST": "localhost:7676",
        "CONNECTION": "keep-alive",
        "METHOD": "POST",
        "SIGNATURE": 'indexed="?0";signify="0BAo0wmWUJRG6a_-kmdeYWRhVdjifc9Dp7cEWxpFpLp4fUf114pb7Qec3r43uqGWfQdu33ci5PTDFgcIiDjsDPMI"',
        "SIGNATURE-INPUT": 'signify=("@method" "@path" "signify-resource" "signify-timestamp");created=1737497943;keyid="BAIGwtGP4CFwVqXiU9bspN5_eoWpPfNh9qChkK6FtDAu";alg="ed25519"',
        "SIGNIFY-RESOURCE": 'EC3Rm0f9aQiZz2hxZOIup5Soyu6x_aA5996LP-eN6hBu',
        "SIGNIFY-TIMESTAMP": "2025-01-21T22:19:03.646000+00:00",
        "ACCEPT": "*/*",
        "ACCEPT-LANGUAGE": "*",
        "SEC-FETCH-MODE": "cors",
        "USER-AGENT": "node",
        "ACCEPT-ENCODING": "gzip, deflate",
    }
    scope = dict(type="http", headers=Headers(headers).raw, method="POST", path="/")
    req = fastapi.Request(scope)
    aid, sig, ser = signed_headers_verifier.VerifySignedHeaders.handle_headers(req)
    assert aid == AID
    assert (
        sig
        == "0BAo0wmWUJRG6a_-kmdeYWRhVdjifc9Dp7cEWxpFpLp4fUf114pb7Qec3r43uqGWfQdu33ci5PTDFgcIiDjsDPMI"
    )