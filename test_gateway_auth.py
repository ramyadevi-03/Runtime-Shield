from gateway_auth import (
    extract_bearer_token,
    gateway_api_key_matches,
    is_gateway_api_key_configured,
)


def test_extract_bearer_token_requires_one_bearer_credential():
    assert extract_bearer_token("Bearer abc") == "abc"
    assert extract_bearer_token("bearer abc") == "abc"
    assert extract_bearer_token(None) is None
    assert extract_bearer_token("Basic abc") is None
    assert extract_bearer_token("Bearer abc extra") is None


def test_gateway_api_key_configuration_requires_url_safe_secret():
    assert is_gateway_api_key_configured("a" * 32)
    assert not is_gateway_api_key_configured("")
    assert not is_gateway_api_key_configured("short")
    assert not is_gateway_api_key_configured("a" * 31 + "!")


def test_gateway_api_key_matches_exactly():
    assert gateway_api_key_matches("secret-value", "secret-value")
    assert not gateway_api_key_matches("secret-value", "other-value")
    assert not gateway_api_key_matches("secret-value", "non-ascii-\N{SNOWMAN}")
    assert not gateway_api_key_matches("", "secret-value")
    assert not gateway_api_key_matches("secret-value", None)
