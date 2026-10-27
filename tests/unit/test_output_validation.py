"""Output checks govern the actual delivery text, including obfuscated secrets."""
from kavach_guard.output_validator import OutputValidator


def test_bearer_credential_is_redacted():
    result = OutputValidator().validate("Authorization: Bearer abcdefghijklmnopqrstuvwxyz12345")
    assert result.is_safe is False
    assert "abcdefghijklmnopqrstuvwxyz12345" not in result.validated_response


def test_zero_width_secret_is_not_delivered():
    result = OutputValidator().validate("SECRET\u200b_KEY_BANK_ALPHA_99")
    assert result.secret_leaked is True
    assert "BANK_ALPHA_99" not in result.validated_response


def test_public_ifsc_is_preserved():
    result = OutputValidator().validate("The branch IFSC is SBIN0001234.")
    assert result.is_safe is True
    assert result.validated_response == "The branch IFSC is SBIN0001234."


def test_full_card_redaction_takes_precedence_over_overlapping_aadhaar():
    result = OutputValidator().validate("Card: 4111 1111 1111 1111")
    assert result.is_safe is False
    assert result.validated_response == "Card: [CARD REDACTED]"
