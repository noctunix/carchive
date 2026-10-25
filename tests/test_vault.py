from __future__ import annotations

import logging
import os
import re
import tomllib
from pathlib import Path
from typing import Any

import pytest
import tomli_w

from carchive import config
from carchive.config import (
    ConfigError,
    WriteOutcome,
    check_passwords_replaceable,
    inspect_vault,
    load_operator_hash,
    load_secrets,
    read_credential_fields,
    remove_credentials,
    replace_password,
    replace_passwords,
    unreadable_credential_refs,
    vault_key_path,
    write_credentials,
    write_operator_hash,
)
from carchive.core.redact import redact
from carchive.core.vault import KEY_LENGTH, VaultError, generate_key, is_sealed, seal, unseal

_PASSWORD = "correct-horse-battery-staple"
_OTHER_PASSWORD = "another-unique-secret-value"
_FAKE_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c3ludGhldGljc2FsdA$c3ludGhldGljaGFzaGZvcnRlc3Rz"


def _raw(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _secrets(tmp_path: Path) -> Path:
    return tmp_path / "cfg" / "secrets.toml"


def _plain_file(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o600)
    return path


def _write_key(path: Path, data: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(data)
    path.chmod(mode)
    return path


# --- primitives --------------------------------------------------------------


def test_seal_roundtrip_including_non_ascii() -> None:
    key = generate_key()
    for value in ("pw", "", "pässwörd-€-日本"):
        token = seal(key, "audi", "password", value)
        assert is_sealed(token)
        assert token.startswith("enc:v2:")
        assert unseal(key, "audi", "password", token) == value


def test_generated_keys_have_the_right_length_and_differ() -> None:
    assert len(generate_key()) == KEY_LENGTH
    assert generate_key() != generate_key()


def test_each_seal_uses_a_fresh_nonce() -> None:
    key = generate_key()
    tokens = {seal(key, "audi", "password", _PASSWORD) for _ in range(200)}
    assert len(tokens) == 200


def test_value_is_bound_to_its_reference() -> None:
    key = generate_key()
    token = seal(key, "audi", "password", _PASSWORD)
    with pytest.raises(VaultError) as exc_info:
        unseal(key, "skoda", "password", token)
    assert _PASSWORD not in str(exc_info.value)


def test_value_is_bound_to_its_field() -> None:
    key = generate_key()
    token = seal(key, "audi", "password", _PASSWORD)
    with pytest.raises(VaultError):
        unseal(key, "audi", "user", token)


def test_reference_and_field_boundary_is_unambiguous() -> None:
    key = generate_key()
    token = seal(key, "a", "bc", _PASSWORD)
    with pytest.raises(VaultError):
        unseal(key, "ab", "c", token)
    assert unseal(key, "a", "bc", token) == _PASSWORD


def test_wrong_key_and_tampering_are_detected() -> None:
    key = generate_key()
    token = seal(key, "audi", "password", _PASSWORD)
    with pytest.raises(VaultError):
        unseal(generate_key(), "audi", "password", token)
    flipped = token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1]
    with pytest.raises(VaultError):
        unseal(key, "audi", "password", flipped)


@pytest.mark.parametrize(
    "token", ["plain", "enc:v2:", "enc:v2:!!!!", "enc:v2:AAAA", "enc:v3:AAAA", "enc:v2:" + "A" * 40]
)
def test_malformed_tokens_are_rejected(token: str) -> None:
    with pytest.raises(VaultError):
        unseal(generate_key(), "audi", "password", token)


def test_v1_tokens_are_refused_with_a_clear_message() -> None:
    key = generate_key()
    with pytest.raises(VaultError, match="unsupported sealed-value format"):
        unseal(key, "audi", "password", "enc:v1:" + "A" * 60)
    assert is_sealed("enc:v1:abc")


def test_wrong_key_length_is_rejected() -> None:
    with pytest.raises(VaultError):
        seal(b"short", "audi", "password", "pw")
    with pytest.raises(VaultError):
        unseal(b"short", "audi", "password", "enc:v2:AAAA")


# --- storage -----------------------------------------------------------------


def test_write_encrypts_and_load_decrypts(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)

    outcome = write_credentials(
        secrets_file, "audi", {"user": "me@example.test", "password": _PASSWORD}, overwrite=False
    )

    assert outcome is WriteOutcome.CREATED
    text = secrets_file.read_text()
    assert _PASSWORD not in text
    stored = _raw(secrets_file)["credentials"]["audi"]
    assert stored["user"] == "me@example.test"
    assert stored["password"].startswith("enc:v2:")
    assert load_secrets(secrets_file) == {
        "audi": {"user": "me@example.test", "password": _PASSWORD}
    }


def test_files_and_directory_are_owner_only(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)

    key_file = vault_key_path(secrets_file)
    assert key_file.parent == secrets_file.parent
    assert key_file.stat().st_mode & 0o777 == 0o600
    assert key_file.stat().st_size == KEY_LENGTH
    assert secrets_file.stat().st_mode & 0o777 == 0o600
    assert secrets_file.parent.stat().st_mode & 0o777 == 0o700
    assert [p.name for p in secrets_file.parent.iterdir() if p.name.startswith(".tmp")] == []


def test_loaded_decrypted_values_are_registered_for_redaction(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)

    load_secrets(secrets_file)

    assert redact(f"login with {_PASSWORD} failed") == "login with *** failed"


def test_value_copied_to_another_reference_fails_to_load(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    token = _raw(secrets_file)["credentials"]["audi"]["password"]
    with secrets_file.open("a") as handle:
        handle.write(f'\n[credentials.skoda]\npassword = "{token}"\n')

    with pytest.raises(ConfigError) as exc_info:
        load_secrets(secrets_file)

    message = str(exc_info.value)
    assert "skoda" in message
    assert _PASSWORD not in message
    assert token not in message


def test_value_moved_to_another_field_fails_to_load(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    key = vault_key_path(secrets_file).read_bytes()
    foreign = seal(key, "audi", "user", _OTHER_PASSWORD)
    token = _raw(secrets_file)["credentials"]["audi"]["password"]
    secrets_file.write_text(secrets_file.read_text().replace(token, foreign))

    with pytest.raises(ConfigError, match="'password'") as exc_info:
        load_secrets(secrets_file)

    assert _OTHER_PASSWORD not in str(exc_info.value)


def test_v1_password_is_refused_on_load(tmp_path: Path) -> None:
    secrets_file = _plain_file(
        _secrets(tmp_path),
        '[credentials.audi]\nuser = "me"\npassword = "enc:v1:' + "A" * 60 + '"\n',
    )
    _write_key(vault_key_path(secrets_file), generate_key())

    with pytest.raises(ConfigError, match="unsupported sealed-value format"):
        load_secrets(secrets_file)


def test_user_and_other_fields_stay_plaintext(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(
        secrets_file,
        "audi",
        {"user": "me@example.test", "region": "eu", "password": _PASSWORD},
        overwrite=False,
    )

    text = secrets_file.read_text()
    assert 'user = "me@example.test"' in text
    assert 'region = "eu"' in text
    assert _PASSWORD not in text
    stored = _raw(secrets_file)["credentials"]["audi"]
    assert stored["password"].startswith("enc:v2:")
    assert load_secrets(secrets_file)["audi"]["region"] == "eu"


def test_credential_without_password_needs_no_key(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)

    write_credentials(secrets_file, "audi", {"user": "me"}, overwrite=False)

    assert not vault_key_path(secrets_file).exists()
    assert load_secrets(secrets_file) == {"audi": {"user": "me"}}


def test_tampered_ciphertext_fails_closed_without_leaking(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    token = _raw(secrets_file)["credentials"]["audi"]["password"]
    flipped = token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1]
    secrets_file.write_text(secrets_file.read_text().replace(token, flipped))

    with pytest.raises(ConfigError) as exc_info:
        load_secrets(secrets_file)

    assert _PASSWORD not in str(exc_info.value)
    assert flipped not in str(exc_info.value)


def test_replaced_key_fails_closed(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    _write_key(vault_key_path(secrets_file), generate_key())

    with pytest.raises(ConfigError, match="cannot decrypt"):
        load_secrets(secrets_file)
    with pytest.raises(ConfigError):
        write_credentials(secrets_file, "skoda", {"password": "x" * 8}, overwrite=False)


def test_plaintext_values_load_unchanged_and_do_not_create_a_key(tmp_path: Path) -> None:
    secrets_file = _plain_file(
        _secrets(tmp_path), f'[credentials.audi]\nuser = "me"\npassword = "{_PASSWORD}"\n'
    )

    assert load_secrets(secrets_file) == {"audi": {"user": "me", "password": _PASSWORD}}
    assert not vault_key_path(secrets_file).exists()
    assert redact(_PASSWORD) == "***"


def test_next_write_migrates_all_plaintext_values(tmp_path: Path) -> None:
    secrets_file = _plain_file(
        _secrets(tmp_path), f'[credentials.audi]\nuser = "me"\npassword = "{_PASSWORD}"\n'
    )

    write_credentials(secrets_file, "vw", {"password": _OTHER_PASSWORD}, overwrite=False)

    text = secrets_file.read_text()
    assert _PASSWORD not in text
    assert _OTHER_PASSWORD not in text
    assert vault_key_path(secrets_file).exists()
    assert load_secrets(secrets_file) == {
        "audi": {"user": "me", "password": _PASSWORD},
        "vw": {"password": _OTHER_PASSWORD},
    }


def test_operator_hash_write_also_migrates_plaintext(tmp_path: Path) -> None:
    secrets_file = _plain_file(
        _secrets(tmp_path), f'[credentials.audi]\npassword = "{_PASSWORD}"\n'
    )

    write_operator_hash(secrets_file, _FAKE_HASH)

    assert _PASSWORD not in secrets_file.read_text()
    assert load_secrets(secrets_file) == {"audi": {"password": _PASSWORD}}


def test_repeated_writes_do_not_reencrypt_and_keep_the_key(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    key_before = vault_key_path(secrets_file).read_bytes()
    content_before = secrets_file.read_bytes()

    again = write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)

    assert again is WriteOutcome.UNCHANGED
    assert secrets_file.read_bytes() == content_before

    write_credentials(secrets_file, "vw", {"password": _OTHER_PASSWORD}, overwrite=False)
    write_operator_hash(secrets_file, _FAKE_HASH)

    assert vault_key_path(secrets_file).read_bytes() == key_before
    assert (
        _raw(secrets_file)["credentials"]["audi"]
        == tomllib.loads(content_before.decode())["credentials"]["audi"]
    )
    assert load_secrets(secrets_file)["audi"] == {"password": _PASSWORD}


def test_replacing_a_credential_seals_the_new_value(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)

    outcome = write_credentials(secrets_file, "audi", {"password": _OTHER_PASSWORD}, overwrite=True)

    assert outcome is WriteOutcome.REPLACED
    assert _OTHER_PASSWORD not in secrets_file.read_text()
    assert load_secrets(secrets_file) == {"audi": {"password": _OTHER_PASSWORD}}


def test_values_with_the_reserved_prefix_are_refused(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    with pytest.raises(ConfigError):
        write_credentials(secrets_file, "audi", {"password": "enc:v2:abc"}, overwrite=False)
    with pytest.raises(ConfigError):
        write_credentials(secrets_file, "audi", {"password": "enc:v1:abc"}, overwrite=False)
    assert not secrets_file.exists()


def test_operator_table_is_kept_and_never_encrypted(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_operator_hash(secrets_file, _FAKE_HASH)
    assert not vault_key_path(secrets_file).exists()

    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    assert load_operator_hash(secrets_file) == _FAKE_HASH
    assert _raw(secrets_file)["operator"] == {"password_hash": _FAKE_HASH}

    assert remove_credentials(secrets_file, "audi") is True
    assert _raw(secrets_file)["operator"] == {"password_hash": _FAKE_HASH}


# --- key presence ------------------------------------------------------------


def test_missing_key_with_encrypted_values_fails_and_never_creates_one(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    key_file = vault_key_path(secrets_file)
    key_file.unlink()
    content_before = secrets_file.read_bytes()

    with pytest.raises(ConfigError) as exc_info:
        load_secrets(secrets_file)
    assert "account set-password" in str(exc_info.value)
    assert _PASSWORD not in str(exc_info.value)
    with pytest.raises(ConfigError):
        write_credentials(secrets_file, "vw", {"password": _OTHER_PASSWORD}, overwrite=False)
    with pytest.raises(ConfigError):
        inspect_vault(secrets_file)

    assert not key_file.exists()
    assert secrets_file.read_bytes() == content_before


def test_removing_and_operator_hash_work_without_key_when_nothing_needs_sealing(
    tmp_path: Path,
) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    write_credentials(secrets_file, "vw", {"password": _OTHER_PASSWORD}, overwrite=False)
    vault_key_path(secrets_file).unlink()

    write_operator_hash(secrets_file, _FAKE_HASH)
    assert remove_credentials(secrets_file, "audi") is True

    assert not vault_key_path(secrets_file).exists()
    assert set(_raw(secrets_file)["credentials"]) == {"vw"}


def test_missing_key_with_mixed_values_does_not_create_a_key(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    with secrets_file.open("a") as handle:
        handle.write(f'\n[credentials.vw]\npassword = "{_OTHER_PASSWORD}"\n')
    vault_key_path(secrets_file).unlink()

    with pytest.raises(ConfigError):
        remove_credentials(secrets_file, "audi")
    assert not vault_key_path(secrets_file).exists()


@pytest.mark.parametrize("size", [0, 16, 31, 33, 64])
def test_key_of_wrong_length_is_rejected(tmp_path: Path, size: int) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    _write_key(vault_key_path(secrets_file), b"k" * size)

    with pytest.raises(ConfigError, match="exactly 32 bytes"):
        load_secrets(secrets_file)
    with pytest.raises(ConfigError):
        write_credentials(secrets_file, "vw", {"password": _OTHER_PASSWORD}, overwrite=False)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o644])
def test_key_with_group_or_world_access_is_rejected(tmp_path: Path, mode: int) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    vault_key_path(secrets_file).chmod(mode)

    with pytest.raises(ConfigError, match="chmod 600"):
        load_secrets(secrets_file)


def test_read_only_owner_key_is_accepted(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    vault_key_path(secrets_file).chmod(0o400)

    assert load_secrets(secrets_file) == {"audi": {"password": _PASSWORD}}


def test_symlinked_key_is_rejected(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    key_file = vault_key_path(secrets_file)
    target = _write_key(tmp_path / "elsewhere.key", key_file.read_bytes())
    key_file.unlink()
    key_file.symlink_to(target)

    with pytest.raises(ConfigError, match="regular file"):
        load_secrets(secrets_file)


def test_dangling_symlink_is_not_treated_as_a_missing_key(tmp_path: Path) -> None:
    secrets_file = _plain_file(
        _secrets(tmp_path), f'[credentials.audi]\npassword = "{_PASSWORD}"\n'
    )
    vault_key_path(secrets_file).symlink_to(tmp_path / "nowhere")

    with pytest.raises(ConfigError):
        write_credentials(secrets_file, "vw", {"password": _OTHER_PASSWORD}, overwrite=False)
    assert vault_key_path(secrets_file).is_symlink()


def test_key_that_is_a_directory_is_rejected(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    key_file = vault_key_path(secrets_file)
    key_file.unlink()
    key_file.mkdir(mode=0o700)

    with pytest.raises(ConfigError):
        load_secrets(secrets_file)


def test_key_creation_never_replaces_an_existing_key(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    secrets_file.parent.mkdir(parents=True)
    existing = generate_key()
    _write_key(vault_key_path(secrets_file), existing)

    assert config._create_vault_key(secrets_file) == existing
    assert vault_key_path(secrets_file).read_bytes() == existing
    assert [p.name for p in secrets_file.parent.iterdir()] == ["vault.key"]


def test_error_messages_never_contain_key_material(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    bad_key = b"\x01secret-key-bytes-of-wrong-size"
    _write_key(vault_key_path(secrets_file), bad_key)

    with pytest.raises(ConfigError) as exc_info:
        load_secrets(secrets_file)

    assert "secret-key-bytes" not in str(exc_info.value)


# --- replacing a password ------------------------------------------------------


def test_replace_password_keeps_other_fields_and_references(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"user": "me", "password": _PASSWORD}, overwrite=False)
    write_credentials(secrets_file, "vw", {"password": _OTHER_PASSWORD}, overwrite=False)
    key_before = vault_key_path(secrets_file).read_bytes()

    replace_password(secrets_file, "audi", "fresh-password-value")

    assert vault_key_path(secrets_file).read_bytes() == key_before
    assert load_secrets(secrets_file) == {
        "audi": {"user": "me", "password": "fresh-password-value"},
        "vw": {"password": _OTHER_PASSWORD},
    }


def test_replace_password_after_key_loss_creates_a_key_when_nothing_else_is_stranded(
    tmp_path: Path,
) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"user": "me", "password": _PASSWORD}, overwrite=False)
    vault_key_path(secrets_file).unlink()

    replace_password(secrets_file, "audi", "fresh-password-value")

    assert vault_key_path(secrets_file).stat().st_mode & 0o777 == 0o600
    assert load_secrets(secrets_file)["audi"] == {"user": "me", "password": "fresh-password-value"}


def test_replace_password_after_key_loss_refuses_while_other_passwords_are_stranded(
    tmp_path: Path,
) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    write_credentials(secrets_file, "vw", {"password": _OTHER_PASSWORD}, overwrite=False)
    write_credentials(secrets_file, "seat", {"password": _OTHER_PASSWORD + "2"}, overwrite=False)
    vault_key_path(secrets_file).unlink()
    content_before = secrets_file.read_bytes()

    with pytest.raises(ConfigError, match="2 other reference"):
        replace_password(secrets_file, "audi", "fresh-password-value")

    assert not vault_key_path(secrets_file).exists()
    assert secrets_file.read_bytes() == content_before


def _three_references_with_lost_key(tmp_path: Path) -> Path:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"user": "a", "password": _PASSWORD}, overwrite=False)
    write_credentials(secrets_file, "vw", {"password": _OTHER_PASSWORD}, overwrite=False)
    write_credentials(secrets_file, "seat", {"password": _OTHER_PASSWORD + "2"}, overwrite=False)
    vault_key_path(secrets_file).unlink()
    return secrets_file


def test_unreadable_refs_are_all_sealed_references_when_the_key_is_missing(
    tmp_path: Path,
) -> None:
    secrets_file = _three_references_with_lost_key(tmp_path)

    assert unreadable_credential_refs(secrets_file) == ["audi", "seat", "vw"]


def test_unreadable_refs_are_empty_for_readable_plaintext_and_missing_files(
    tmp_path: Path,
) -> None:
    secrets_file = _secrets(tmp_path)
    assert unreadable_credential_refs(secrets_file) == []
    _plain_file(secrets_file, '[credentials.audi]\npassword = "plain"\n')

    assert unreadable_credential_refs(secrets_file) == []


def test_unreadable_refs_with_a_wrong_key_name_only_the_failing_references(
    tmp_path: Path,
) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    key = vault_key_path(secrets_file).read_bytes()
    document = _raw(secrets_file)
    document["credentials"]["vw"] = {"password": seal(generate_key(), "vw", "password", "x")}
    secrets_file.write_text(tomli_w.dumps(document))
    assert vault_key_path(secrets_file).read_bytes() == key

    assert unreadable_credential_refs(secrets_file) == ["vw"]


def test_replace_passwords_replaces_all_unreadable_references_in_one_write(
    tmp_path: Path,
) -> None:
    secrets_file = _three_references_with_lost_key(tmp_path)

    replace_passwords(secrets_file, {"audi": "new-a", "vw": "new-v", "seat": "new-s"})

    assert vault_key_path(secrets_file).stat().st_mode & 0o777 == 0o600
    assert load_secrets(secrets_file) == {
        "audi": {"user": "a", "password": "new-a"},
        "vw": {"password": "new-v"},
        "seat": {"password": "new-s"},
    }
    assert unreadable_credential_refs(secrets_file) == []


def test_replace_passwords_with_a_partial_set_after_key_loss_writes_nothing(
    tmp_path: Path,
) -> None:
    secrets_file = _three_references_with_lost_key(tmp_path)
    content_before = secrets_file.read_bytes()

    with pytest.raises(ConfigError, match=r"1 other reference\(s\) \(seat\)"):
        replace_passwords(secrets_file, {"audi": "new-a", "vw": "new-v"})

    assert secrets_file.read_bytes() == content_before
    assert not vault_key_path(secrets_file).exists()


def test_replace_passwords_validates_everything_before_writing(tmp_path: Path) -> None:
    secrets_file = _three_references_with_lost_key(tmp_path)
    content_before = secrets_file.read_bytes()

    with pytest.raises(ConfigError, match="no passwords"):
        replace_passwords(secrets_file, {})
    with pytest.raises(ConfigError, match="no stored credentials"):
        replace_passwords(secrets_file, {"audi": "new-a", "nope": "x"})
    with pytest.raises(ConfigError, match="reserved prefix"):
        replace_passwords(secrets_file, {"audi": "new-a", "vw": "enc:v2:abc"})

    assert secrets_file.read_bytes() == content_before


def test_check_passwords_replaceable_names_the_stranded_references(tmp_path: Path) -> None:
    secrets_file = _three_references_with_lost_key(tmp_path)

    with pytest.raises(ConfigError, match=r"2 other reference\(s\) \(seat, vw\)") as exc_info:
        check_passwords_replaceable(secrets_file, ["audi"])

    assert "without a label" in str(exc_info.value)
    check_passwords_replaceable(secrets_file, ["audi", "vw", "seat"])


def test_replace_password_rejects_unknown_reference_and_reserved_prefix(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"password": _PASSWORD}, overwrite=False)
    content_before = secrets_file.read_bytes()

    with pytest.raises(ConfigError, match="no stored credentials"):
        replace_password(secrets_file, "vw", "fresh-password-value")
    with pytest.raises(ConfigError, match="reserved prefix"):
        replace_password(secrets_file, "audi", "enc:v2:abc")

    assert secrets_file.read_bytes() == content_before


def test_read_credential_fields_omits_the_password_and_needs_no_key(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    write_credentials(secrets_file, "audi", {"user": "me", "password": _PASSWORD}, overwrite=False)
    vault_key_path(secrets_file).unlink()

    assert read_credential_fields(secrets_file, "audi") == {"user": "me"}
    assert read_credential_fields(secrets_file, "vw") is None
    assert read_credential_fields(_secrets(tmp_path / "other"), "audi") is None


# --- status and logging --------------------------------------------------------


def test_inspect_vault_counts_values_without_decrypting(tmp_path: Path) -> None:
    secrets_file = _secrets(tmp_path)
    assert inspect_vault(secrets_file).key_present is False

    _plain_file(secrets_file, '[credentials.audi]\nuser = "me"\npassword = "pw-value"\n')
    status = inspect_vault(secrets_file)
    assert (status.key_present, status.sealed_values, status.plaintext_values) == (False, 0, 1)

    write_credentials(secrets_file, "vw", {"password": _OTHER_PASSWORD}, overwrite=False)
    status = inspect_vault(secrets_file)
    assert (status.key_present, status.sealed_values, status.plaintext_values) == (True, 2, 0)


def test_passwords_never_appear_in_logs_or_exception_texts(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    secrets_file = _secrets(tmp_path)
    texts: list[str] = []

    write_credentials(secrets_file, "audi", {"user": "me", "password": _PASSWORD}, overwrite=False)
    load_secrets(secrets_file)
    inspect_vault(secrets_file)
    key_file = vault_key_path(secrets_file)
    good_key = key_file.read_bytes()

    for key_bytes, mode in ((b"short", 0o600), (good_key, 0o644), (generate_key(), 0o600)):
        _write_key(key_file, key_bytes, mode)
        for action in (
            lambda: load_secrets(secrets_file),
            lambda: write_credentials(
                secrets_file, "x", {"password": _OTHER_PASSWORD}, overwrite=True
            ),
        ):
            with pytest.raises(ConfigError) as exc_info:
                action()
            texts.append(str(exc_info.value))
    key_file.unlink()
    with pytest.raises(ConfigError) as exc_info:
        load_secrets(secrets_file)
    texts.append(str(exc_info.value))

    everything = "\n".join([*texts, caplog.text, *(r.getMessage() for r in caplog.records)])
    assert _PASSWORD not in everything
    assert _OTHER_PASSWORD not in everything
    assert not re.search(r"enc:v2:[A-Za-z0-9_-]{20,}", everything)
    assert os.fspath(key_file) in everything
