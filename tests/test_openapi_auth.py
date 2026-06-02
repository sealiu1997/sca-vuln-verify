from sca_vuln_verify.adapters.sca_openapi_auth import (
    build_auth_headers,
    canonicalize_query_string,
    hash_payload,
)


def test_openapi_signature_matches_document_example():
    # The OpenAPI document's displayed JSON includes spaces, but the documented
    # SHA256 digest and signature correspond to this exact compact byte payload.
    body = b'{"username":"hell","password":"world"}'

    headers = build_auth_headers(
        access_key="1234567890",
        secret_key="0987654321",
        method="POST",
        body=body,
        timestamp="1624520733",
        nonce="e616388b-2509-4d29-834d-473d0f7756d2",
    )

    assert hash_payload(body) == "52af665b285c1158ba0c801eecd5a898b0ddcdacabe2a865fb5946c54627b1cd"
    # The documented Signature value does not match the documented
    # StringToSign + SecretKey. This expected value is produced by the stated
    # HMAC-SHA256 algorithm.
    assert headers["Signature"] == "BHvW2Y0JruKvTghmJEbsGYdyBAMhfi1/Ckpfg8R5+y4="
    assert headers["SignatureVersion"] == "1.0"
    assert headers["SignatureMethod"] == "HMAC-SHA256"


def test_query_params_are_sorted_before_signing():
    assert canonicalize_query_string({"z": "last", "a": "first", "m": 2}) == "a=first&m=2&z=last"


def test_signing_does_not_mutate_body_bytes():
    body = b"payload"
    original = bytes(body)

    build_auth_headers(
        access_key="ak",
        secret_key="sk",
        method="POST",
        body=body,
        timestamp="1",
        nonce="n",
    )

    assert body == original


def test_multipart_payload_hash_uses_first_4kb():
    body = b"a" * (5 * 1024)

    assert hash_payload(body, is_multipart=True) == hash_payload(body[: 4 * 1024])
    assert hash_payload(body, is_multipart=True) != hash_payload(body)


def test_generated_nonce_changes_between_calls():
    first = build_auth_headers(access_key="ak", secret_key="sk", method="GET")
    second = build_auth_headers(access_key="ak", secret_key="sk", method="GET")

    assert first["SignatureNonce"] != second["SignatureNonce"]
