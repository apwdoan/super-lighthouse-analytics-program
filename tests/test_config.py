"""Writing one setting back into a user-owned TOML file.

tomllib is read-only, so the writer is a surgical text edit, and everything
here is about the two ways such an edit can betray a user: destroying the
rest of their file, or writing something the reader cannot read back.
"""

from __future__ import annotations

import pytest

from slap.config import Settings, save_crux_api_key

HAND_WRITTEN = """\
# My config. Do not lose this comment.
db_path = "D:/audits/slap.sqlite3"

[lighthouse]
# median of five, because the client asked
runs = 5

[collector]
timeout = 20.0

[branding]
company_name = "Acme Web"
"""


def test_saving_into_a_missing_file_creates_a_readable_one(tmp_path):
    path = tmp_path / "config.toml"
    save_crux_api_key("AIzaSyFAKE-KEY_1234567890", path)
    loaded = Settings.load(path)
    assert loaded.collector.crux_api_key == "AIzaSyFAKE-KEY_1234567890"
    assert loaded.config_path == path


def test_the_rest_of_the_file_survives_byte_for_byte(tmp_path):
    """The reason this is a text edit and not parse-and-rewrite: the file is
    user-owned, and a settings page that eats their comments and reorders
    their sections to change one line is vandalism with a save button."""
    path = tmp_path / "config.toml"
    path.write_text(HAND_WRITTEN, encoding="utf-8")

    save_crux_api_key("AIzaSyFAKE-KEY_1234567890", path)
    text = path.read_text(encoding="utf-8")

    assert "# My config. Do not lose this comment." in text
    assert "# median of five, because the client asked" in text
    assert 'company_name = "Acme Web"' in text
    assert "timeout = 20.0" in text
    assert 'crux_api_key = "AIzaSyFAKE-KEY_1234567890"' in text
    # And the reader agrees about every part of it.
    loaded = Settings.load(path)
    assert loaded.collector.crux_api_key == "AIzaSyFAKE-KEY_1234567890"
    assert loaded.collector.timeout == 20.0
    assert loaded.lighthouse.runs == 5
    assert loaded.branding["company_name"] == "Acme Web"


def test_an_existing_key_is_replaced_in_place(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(HAND_WRITTEN.replace(
        "[collector]\ntimeout = 20.0",
        '[collector]\ncrux_api_key = "AIzaSyOLD-KEY_00000000"\ntimeout = 20.0'),
        encoding="utf-8")

    save_crux_api_key("AIzaSyNEW-KEY_1111111111", path)
    text = path.read_text(encoding="utf-8")
    assert "AIzaSyOLD" not in text
    assert text.count("crux_api_key") == 1
    assert Settings.load(path).collector.crux_api_key == "AIzaSyNEW-KEY_1111111111"


def test_clearing_removes_the_line_and_nothing_else(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(HAND_WRITTEN.replace(
        "[collector]\ntimeout = 20.0",
        '[collector]\ncrux_api_key = "AIzaSyOLD-KEY_00000000"\ntimeout = 20.0'),
        encoding="utf-8")

    save_crux_api_key(None, path)
    text = path.read_text(encoding="utf-8")
    assert "crux_api_key" not in text
    assert "timeout = 20.0" in text
    assert "# My config. Do not lose this comment." in text
    assert Settings.load(path).collector.crux_api_key is None


def test_clearing_when_nothing_is_stored_writes_nothing(tmp_path):
    path = tmp_path / "config.toml"
    save_crux_api_key("", path)
    assert not path.exists()


def test_a_key_that_could_break_the_file_is_refused(tmp_path):
    """The failure mode of writing an arbitrary string into a quoted TOML
    value is an injection into a file the whole app reads at startup."""
    path = tmp_path / "config.toml"
    path.write_text(HAND_WRITTEN, encoding="utf-8")
    for bad in ('AIza"\\ninjected = true', "key with spaces", "short", "",
                "x" * 500):
        with pytest.raises(ValueError):
            save_crux_api_key(bad or "\"", path)
    assert path.read_text(encoding="utf-8") == HAND_WRITTEN


def test_settings_load_records_where_it_read_from(tmp_path):
    path = tmp_path / "somewhere.toml"
    assert Settings.load(path).config_path == path
    assert Settings().config_path is None
