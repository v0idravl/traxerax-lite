"""Tests for host state collectors."""

import json
import os
import pwd
import socket
from datetime import datetime, timezone

from traxerax_lite.config import HostSettings
from traxerax_lite.host_collectors import (
    _MAX_COLLECTED_FILE_BYTES,
    _chromium_permissions,
    _parse_desktop_entry,
    _parse_proc_net_addr,
    collect_host_state,
    persistable_host_records,
)
from traxerax_lite.host_models import HostStateRecord


def _fake_pwall(home, name="alice", uid=1000):
    """A pwd.getpwall() replacement pointing one user at a temp home dir."""
    return [
        pwd.struct_passwd((name, "x", uid, uid, name, str(home), "/bin/bash"))
    ]


def _collect(collector, settings=None):
    return collect_host_state(
        settings or HostSettings(enabled_collectors={collector}),
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
    )


def test_collect_host_state_returns_records_and_skips(tmp_path):
    """Collectors should produce records and report what they cannot read."""
    settings = HostSettings(enabled_collectors={"users"})
    records, skipped = collect_host_state(
        settings,
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
    )
    assert records
    assert all(record.source == "users" for record in records)
    assert isinstance(skipped, list)


def test_disabled_collectors_are_not_run():
    """Only enabled collectors should run."""
    settings = HostSettings(enabled_collectors=set())
    records, skipped = collect_host_state(
        settings,
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
    )
    assert records == []
    assert skipped == []


def test_parse_proc_net_addr_ipv4():
    """IPv4 addresses in /proc/net format are little-endian hex."""
    addr, port = _parse_proc_net_addr("0100007F:1F90")
    assert addr == "127.0.0.1"
    assert port == 8080


def test_parse_proc_net_addr_ipv6():
    """IPv6 addresses in /proc/net format are 32 hex chars."""
    addr, port = _parse_proc_net_addr("00000000000000000000000000000000:0016")
    assert addr == "::"
    assert port == 22


def test_host_state_record_hash_ignores_run_id():
    """Identical host state should hash the same across different runs."""
    timestamp = datetime.now(timezone.utc)
    first = HostStateRecord(
        run_id="run-1",
        timestamp=timestamp,
        source="users",
        record_type="user_account",
        data={"username": "alice", "uid": 1000},
    )
    second = HostStateRecord(
        run_id="run-2",
        timestamp=timestamp,
        source="users",
        record_type="user_account",
        data={"username": "alice", "uid": 1000},
    )

    assert first.record_hash == second.record_hash


def test_socket_fds_collector_finds_own_socket():
    """The socket_fds collector should map our own socket inode to our pid."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        inode = int(
            os.readlink(f"/proc/self/fd/{listener.fileno()}")[8:-1]
        )
        settings = HostSettings(enabled_collectors={"socket_fds"})
        records, skipped = collect_host_state(
            settings,
            run_id="run-1",
            timestamp=datetime.now(timezone.utc),
        )
    finally:
        listener.close()

    assert skipped == []
    ours = [
        r
        for r in records
        if r.data["pid"] == os.getpid() and r.data["inode"] == inode
    ]
    assert len(ours) == 1
    assert ours[0].source == "socket_fds"
    assert ours[0].record_type == "process_socket_fd"
    assert ours[0].data["comm"]


def test_socket_fds_collector_never_raises_on_inaccessible_proc():
    """Permission errors on other users' /proc/<pid>/fd are skipped silently."""
    settings = HostSettings(enabled_collectors={"socket_fds"})
    records, skipped = collect_host_state(
        settings,
        run_id="run-1",
        timestamp=datetime.now(timezone.utc),
    )
    assert isinstance(records, list)
    assert skipped == []
    assert all(r.record_type == "process_socket_fd" for r in records)


def test_persistable_host_records_drops_ephemeral_types():
    """process_socket_fd records must never reach host_state_records."""
    timestamp = datetime.now(timezone.utc)
    ephemeral = HostStateRecord(
        run_id="run-1",
        timestamp=timestamp,
        source="socket_fds",
        record_type="process_socket_fd",
        data={"pid": 1, "comm": "init", "inode": 12345},
    )
    persistent = HostStateRecord(
        run_id="run-1",
        timestamp=timestamp,
        source="network",
        record_type="socket_tcp",
        data={"proto": "tcp", "state": "LISTEN", "inode": 12345},
    )

    result = persistable_host_records([ephemeral, persistent])

    assert result == [persistent]


def test_authorized_keys_symlink_is_skipped(tmp_path, monkeypatch):
    """A symlinked authorized_keys must not leak its target's content."""
    home = tmp_path / "alice"
    (home / ".ssh").mkdir(parents=True)
    secret = tmp_path / "shadow-copy"
    secret.write_text("root:$6$hash:19000:0:99999:7:::\n")
    (home / ".ssh" / "authorized_keys").symlink_to(secret)
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(home))

    records, skipped = _collect("authorized_keys")

    assert records == []
    assert skipped == []


def test_authorized_keys_regular_file_is_collected(tmp_path, monkeypatch):
    """A regular authorized_keys file is still collected with its content."""
    home = tmp_path / "alice"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text(
        "# comment\nssh-ed25519 AAAA key\n\nssh-ed25519 BBBB key2\n"
    )
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(home))

    records, skipped = _collect("authorized_keys")

    assert skipped == []
    assert len(records) == 1
    assert records[0].data["user"] == "alice"
    assert records[0].data["key_count"] == 2
    assert "ssh-ed25519 AAAA key" in records[0].data["content"]


def test_shell_profile_symlink_is_skipped(tmp_path, monkeypatch):
    """A symlinked ~/.bashrc must not leak its target's content."""
    home = tmp_path / "alice"
    home.mkdir()
    secret = tmp_path / "shadow-copy"
    secret.write_text("root:$6$hash:19000:0:99999:7:::\n")
    (home / ".bashrc").symlink_to(secret)
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(home))

    records, skipped = _collect("shell_profiles")

    assert skipped == []
    assert [r for r in records if r.data.get("user") == "alice"] == []


def test_shell_profile_oversized_file_is_truncated(tmp_path, monkeypatch):
    """An oversized profile file is capped, not fatal to the collector."""
    home = tmp_path / "alice"
    home.mkdir()
    (home / ".bashrc").write_text("x" * (_MAX_COLLECTED_FILE_BYTES + 1000))
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(home))

    records, skipped = _collect("shell_profiles")

    assert skipped == []
    user_records = [r for r in records if r.data.get("user") == "alice"]
    assert len(user_records) == 1
    assert len(user_records[0].data["content"]) == _MAX_COLLECTED_FILE_BYTES


def test_parse_desktop_entry_extracts_fields():
    """Name, Exec, and Hidden=true should be parsed from a .desktop file."""
    text = (
        "[Desktop Entry]\n"
        "Name=Updater\n"
        "Comment=updates things\n"
        "Exec=/opt/updater/run.sh --quiet\n"
        "Hidden=true\n"
    )

    name, exec_line, hidden = _parse_desktop_entry(text)

    assert name == "Updater"
    assert exec_line == "/opt/updater/run.sh --quiet"
    assert hidden is True


def test_parse_desktop_entry_defaults_for_missing_keys():
    """A script without desktop keys yields Nones and hidden False."""
    name, exec_line, hidden = _parse_desktop_entry("#!/bin/sh\nexport X=1\n")

    assert name is None
    assert exec_line is None
    assert hidden is False


def test_parse_desktop_entry_first_value_wins_and_hidden_false():
    """Duplicate keys keep the first value; Hidden=false is not hidden."""
    text = "Name=First\nName=Second\nExec=/bin/a\nExec=/bin/b\nHidden=false\n"

    name, exec_line, hidden = _parse_desktop_entry(text)

    assert name == "First"
    assert exec_line == "/bin/a"
    assert hidden is False


def test_xdg_autostart_collects_system_and_user_entries(tmp_path, monkeypatch):
    """System dirs and all three per-user locations should be collected."""
    system_dir = tmp_path / "xdg-autostart"
    system_dir.mkdir()
    (system_dir / "updater.desktop").write_text(
        "[Desktop Entry]\nName=Updater\nExec=/opt/updater/run\n"
    )

    home = tmp_path / "alice"
    autostart = home / ".config" / "autostart"
    autostart.mkdir(parents=True)
    (autostart / "notes.desktop").write_text(
        "[Desktop Entry]\nName=Notes\nExec=/usr/bin/notes\nHidden=true\n"
    )
    scripts = home / ".config" / "autostart-scripts"
    scripts.mkdir(parents=True)
    (scripts / "setup.sh").write_text("#!/bin/sh\nexport X=1\n")
    env_dir = home / ".config" / "plasma-workspace" / "env"
    env_dir.mkdir(parents=True)
    (env_dir / "path.sh").write_text("export PATH=$HOME/bin:$PATH\n")

    monkeypatch.setattr(
        "traxerax_lite.host_collectors._XDG_SYSTEM_AUTOSTART_DIRS",
        (system_dir,),
    )
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(home))

    records, skipped = _collect("xdg_autostart")

    assert skipped == []
    assert len(records) == 4
    assert all(r.record_type == "xdg_autostart_entry" for r in records)
    assert all(r.source == "xdg_autostart" for r in records)
    by_path = {r.data["path"]: r.data for r in records}

    system = by_path[str(system_dir / "updater.desktop")]
    assert system["user"] is None
    assert system["name"] == "Updater"
    assert system["exec"] == "/opt/updater/run"
    assert system["hidden"] is False

    notes = by_path[str(autostart / "notes.desktop")]
    assert notes["user"] == "alice"
    assert notes["name"] == "Notes"
    assert notes["hidden"] is True

    script = by_path[str(scripts / "setup.sh")]
    assert script["user"] == "alice"
    assert script["name"] is None
    assert "export X=1" in script["content"]

    env = by_path[str(env_dir / "path.sh")]
    assert env["user"] == "alice"


def test_xdg_autostart_user_symlink_is_skipped(tmp_path, monkeypatch):
    """A symlinked user autostart entry must not leak its target's content."""
    home = tmp_path / "alice"
    autostart = home / ".config" / "autostart"
    autostart.mkdir(parents=True)
    secret = tmp_path / "shadow-copy"
    secret.write_text("root:$6$hash:19000:0:99999:7:::\n")
    (autostart / "evil.desktop").symlink_to(secret)

    monkeypatch.setattr(
        "traxerax_lite.host_collectors._XDG_SYSTEM_AUTOSTART_DIRS",
        (tmp_path / "empty-system",),
    )
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(home))

    records, skipped = _collect("xdg_autostart")

    assert records == []
    assert skipped == []


def test_xdg_autostart_missing_dirs_are_silent(tmp_path, monkeypatch):
    """Hosts without any autostart dirs produce no records and no skips."""
    monkeypatch.setattr(
        "traxerax_lite.host_collectors._XDG_SYSTEM_AUTOSTART_DIRS",
        (tmp_path / "absent",),
    )
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(tmp_path / "alice"))

    records, skipped = _collect("xdg_autostart")

    assert records == []
    assert skipped == []


def test_systemd_user_units_collects_files_and_links(tmp_path, monkeypatch):
    """Unit files carry content; enablement links carry their targets."""
    system_root = tmp_path / "systemd-user"
    wants = system_root / "default.target.wants"
    wants.mkdir(parents=True)
    (system_root / "pipewire.service").write_text(
        "[Service]\nExecStart=/usr/bin/pipewire\n"
    )
    (wants / "pipewire.service").symlink_to("../pipewire.service")

    home = tmp_path / "alice"
    user_root = home / ".config" / "systemd" / "user"
    (user_root / "timers.target.wants").mkdir(parents=True)
    (user_root / "backup.timer").write_text("[Timer]\nOnCalendar=daily\n")
    (user_root / "timers.target.wants" / "backup.timer").symlink_to(
        user_root / "backup.timer"
    )

    monkeypatch.setattr(
        "traxerax_lite.host_collectors._SYSTEMD_USER_UNIT_DIRS",
        (system_root,),
    )
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(home))

    records, skipped = _collect("systemd_user_units")

    assert skipped == []
    assert len(records) == 4
    assert all(r.record_type == "systemd_user_unit" for r in records)
    by_path = {r.data["path"]: r.data for r in records}

    unit = by_path[str(system_root / "pipewire.service")]
    assert unit["user"] is None
    assert unit["link_target"] is None
    assert "ExecStart=/usr/bin/pipewire" in unit["content"]

    link = by_path[str(wants / "pipewire.service")]
    assert link["link_target"] == "../pipewire.service"
    assert link["content"] is None

    user_unit = by_path[str(user_root / "backup.timer")]
    assert user_unit["user"] == "alice"
    assert "OnCalendar=daily" in user_unit["content"]

    user_link = by_path[str(user_root / "timers.target.wants" / "backup.timer")]
    assert user_link["user"] == "alice"
    assert user_link["link_target"] == str(user_root / "backup.timer")
    assert user_link["content"] is None


def test_systemd_user_units_missing_roots_are_silent(tmp_path, monkeypatch):
    """Missing unit trees produce no records and no skips."""
    monkeypatch.setattr(
        "traxerax_lite.host_collectors._SYSTEMD_USER_UNIT_DIRS",
        (tmp_path / "absent",),
    )
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(tmp_path / "alice"))

    records, skipped = _collect("systemd_user_units")

    assert records == []
    assert skipped == []


def _write_sysfs_device(root, name, **attrs):
    """Create a fake sysfs device/interface node with the given attributes."""
    node = root / name
    node.mkdir(parents=True)
    for key, value in attrs.items():
        (node / key).write_text(f"{value}\n")
    return node


def test_usb_devices_inventory(tmp_path, monkeypatch):
    """Devices record their identity; interfaces contribute their classes."""
    root = tmp_path / "usb"
    _write_sysfs_device(
        root,
        "1-2",
        idVendor="046d",
        idProduct="c52b",
        serial="ABC123",
        manufacturer="Logitech",
        product="Unifying Receiver",
        bDeviceClass="00",
    )
    _write_sysfs_device(root, "1-2:1.0", bInterfaceClass="03")
    _write_sysfs_device(root, "1-2:1.1", bInterfaceClass="08")
    _write_sysfs_device(
        root, "usb1", idVendor="1d6b", idProduct="0002",
        product="xHCI Host Controller",
    )

    monkeypatch.setattr(
        "traxerax_lite.host_collectors._USB_DEVICES_ROOT", root
    )

    records, skipped = _collect("usb_devices")

    assert skipped == []
    assert len(records) == 2
    assert all(r.record_type == "usb_device" for r in records)
    by_name = {r.data["name"]: r.data for r in records}

    device = by_name["046d:c52b:ABC123"]
    assert device["sysfs_name"] == "1-2"
    assert device["interface_classes"] == ["03", "08"]
    assert device["manufacturer"] == "Logitech"
    assert device["device_class"] == "00"

    # A root hub without a serial falls back to its sysfs name.
    hub = by_name["1d6b:0002:usb1"]
    assert hub["serial"] == ""
    assert hub["interface_classes"] == []


def test_usb_devices_missing_sysfs_root_is_silent(tmp_path, monkeypatch):
    """Hosts without USB sysfs (containers, VMs) degrade to empty output."""
    monkeypatch.setattr(
        "traxerax_lite.host_collectors._USB_DEVICES_ROOT",
        tmp_path / "absent",
    )

    records, skipped = _collect("usb_devices")

    assert records == []
    assert skipped == []


def test_usb_devices_skips_device_without_idvendor(tmp_path, monkeypatch):
    """A device dir missing idVendor is skipped without killing the run."""
    root = tmp_path / "usb"
    _write_sysfs_device(root, "2-1", idProduct="0001")
    _write_sysfs_device(root, "3-1", idVendor="0781", idProduct="5567")

    monkeypatch.setattr(
        "traxerax_lite.host_collectors._USB_DEVICES_ROOT", root
    )

    records, skipped = _collect("usb_devices")

    assert skipped == []
    assert [r.data["name"] for r in records] == ["0781:5567:3-1"]


def test_chromium_permissions_merges_all_sources():
    """permissions, host_permissions, and content_scripts matches merge."""
    manifest = {
        "permissions": ["tabs", "nativeMessaging"],
        "host_permissions": ["https://*.example.com/*"],
        "content_scripts": [{"matches": ["<all_urls>"]}, {"js": ["x.js"]}],
    }

    assert _chromium_permissions(manifest) == [
        "<all_urls>",
        "https://*.example.com/*",
        "nativeMessaging",
        "tabs",
    ]


def test_chromium_permissions_ignores_malformed_values():
    """Non-list values and non-dict content scripts are ignored."""
    manifest = {
        "permissions": "tabs",
        "host_permissions": None,
        "content_scripts": ["not-a-dict"],
    }

    assert _chromium_permissions(manifest) == []


def _chromium_preferences(**settings):
    return json.dumps({"extensions": {"settings": settings}})


def test_browser_extensions_chromium_and_firefox(tmp_path, monkeypatch):
    """Chromium Preferences and Firefox extensions.json are both parsed."""
    home = tmp_path / "alice"
    profile = home / ".config" / "google-chrome" / "Default"
    profile.mkdir(parents=True)
    (profile / "Preferences").write_text(
        _chromium_preferences(
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa={
                "state": 1,
                "from_webstore": True,
                "manifest": {
                    "name": "Store Ext",
                    "version": "1.0",
                    "permissions": ["tabs"],
                    "content_scripts": [{"matches": ["<all_urls>"]}],
                },
            },
            bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb={
                "state": 0,
                "manifest": {
                    "name": "Side Ext",
                    "version": "0.1",
                    "permissions": ["nativeMessaging"],
                },
            },
        )
    )

    ff_profile = home / ".mozilla" / "firefox" / "abc.default-release"
    ff_profile.mkdir(parents=True)
    (ff_profile / "extensions.json").write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": "ublock@example.net",
                        "version": "1.50.0",
                        "active": True,
                        "sourceURI": "https://addons.mozilla.org/firefox/downloads/latest/",
                        "defaultLocale": {"name": "uBlock Origin"},
                        "userPermissions": {
                            "permissions": ["tabs", "webRequest"],
                            "origins": ["<all_urls>"],
                        },
                    },
                    {"id": "local@example.com", "active": False},
                ]
            }
        )
    )

    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(home))

    records, skipped = _collect("browser_extensions")

    assert skipped == []
    assert len(records) == 4
    assert all(r.record_type == "browser_extension" for r in records)
    by_name = {r.data["name"]: r.data for r in records}

    store = by_name["alice:chrome:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    assert store["enabled"] is True
    assert store["from_store"] is True
    assert store["install_source"] == "webstore"
    assert store["display_name"] == "Store Ext"
    assert store["permissions"] == ["<all_urls>", "tabs"]

    sideloaded = by_name["alice:chrome:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
    assert sideloaded["enabled"] is False
    assert sideloaded["from_store"] is False
    assert sideloaded["install_source"] == "sideloaded"
    assert sideloaded["permissions"] == ["nativeMessaging"]

    ublock = by_name["alice:firefox:ublock@example.net"]
    assert ublock["enabled"] is True
    assert ublock["from_store"] is True
    assert ublock["display_name"] == "uBlock Origin"
    assert ublock["permissions"] == ["<all_urls>", "tabs", "webRequest"]

    local = by_name["alice:firefox:local@example.com"]
    assert local["enabled"] is False
    assert local["from_store"] is False
    assert local["permissions"] == []


def test_browser_extensions_skips_malformed_preferences(tmp_path, monkeypatch):
    """Corrupt Preferences/extensions.json files are skipped, not fatal."""
    home = tmp_path / "alice"
    profile = home / ".config" / "chromium" / "Default"
    profile.mkdir(parents=True)
    (profile / "Preferences").write_text("{not json")
    ff_profile = home / ".mozilla" / "firefox" / "abc.default"
    ff_profile.mkdir(parents=True)
    (ff_profile / "extensions.json").write_text("{not json either")

    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(home))

    records, skipped = _collect("browser_extensions")

    assert records == []
    assert skipped == []


def test_browser_extensions_no_profiles_is_silent(tmp_path, monkeypatch):
    """A user without browser profiles yields no records and no skips."""
    monkeypatch.setattr(pwd, "getpwall", lambda: _fake_pwall(tmp_path / "alice"))

    records, skipped = _collect("browser_extensions")

    assert records == []
    assert skipped == []
