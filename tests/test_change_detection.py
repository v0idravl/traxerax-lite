"""Tests for cross-run host state change detection logic."""

from datetime import datetime, timezone

from traxerax_lite.change_detection import detect_host_changes
from traxerax_lite.config import ChangeSettings
from traxerax_lite.host_models import HostStateRecord
from traxerax_lite.storage import (
    get_connection,
    initialize_database,
    insert_host_state_record,
)


_TIMESTAMP = datetime(2026, 3, 25, 10, 0, 0, tzinfo=timezone.utc)


def _make_record(record_type, data, source="test"):
    return HostStateRecord(
        run_id="history-run",
        timestamp=_TIMESTAMP,
        source=source,
        record_type=record_type,
        data=data,
    )


def _make_db(tmp_path, history):
    connection = get_connection(str(tmp_path / "test.db"))
    initialize_database(connection)
    for record in history:
        insert_host_state_record(connection, record)
    return connection


def _detect(connection, records, settings=None):
    findings = detect_host_changes(
        connection=connection,
        run_id="current-run",
        timestamp=_TIMESTAMP,
        host_records=records,
        settings=settings if settings is not None else ChangeSettings(),
    )
    connection.close()
    return findings


def _cron_record(path="/etc/cron.d/backup", content="0 3 * * * root backup\n"):
    return _make_record(
        "cron_file",
        {"path": path, "line_count": 1, "content": content},
        source="cron",
    )


def _keys_record(path="/root/.ssh/authorized_keys", content="ssh-ed25519 AAAA key\n"):
    return _make_record(
        "ssh_authorized_keys",
        {
            "user": "root",
            "uid": 0,
            "path": path,
            "key_count": 1,
            "permissions": "600",
            "content": content,
        },
        source="authorized_keys",
    )


def _profile_record(path="/etc/profile", content="export PATH=/usr/bin\n"):
    return _make_record(
        "shell_profile",
        {"path": path, "line_count": 1, "content": content},
        source="shell_profiles",
    )


def _sudoers_record(path="/etc/sudoers", content="root ALL=(ALL) ALL\n"):
    return _make_record(
        "sudoers_file",
        {"path": path, "line_count": 1, "content": content},
        source="sudoers",
    )


def _user_record(name="root", uid=0, shell="/bin/bash"):
    return _make_record(
        "user",
        {"name": name, "uid": uid, "gid": uid, "home": f"/home/{name}", "shell": shell},
        source="users",
    )


def _group_record(name="sudo", members=("root",)):
    return _make_record(
        "group",
        {"name": name, "gid": 27, "members": list(members)},
        source="users",
    )


def _module_record(name="nf_conntrack"):
    return _make_record(
        "kernel_module",
        {"name": name, "size": 16384, "refcount": 1, "dependencies": []},
        source="modules",
    )


def _listen_record(port=22, address="0.0.0.0"):
    return _make_record(
        "socket_tcp",
        {
            "proto": "tcp",
            "local_address": address,
            "local_port": port,
            "remote_address": None,
            "remote_port": None,
            "state": "LISTEN",
            "uid": 0,
            "inode": 12345,
        },
        source="network",
    )


def _unit_record(unit="sshd.service", description="OpenSSH server daemon"):
    return _make_record(
        "systemd_service",
        {
            "unit": unit,
            "load_state": "loaded",
            "active_state": "active",
            "sub_state": "running",
            "description": description,
        },
        source="services",
    )


def test_empty_history_fires_nothing(tmp_path):
    """The very first run is the baseline itself and must stay silent."""
    connection = _make_db(tmp_path, [])

    current = [
        _cron_record(),
        _keys_record(),
        _profile_record(),
        _sudoers_record(),
        _user_record(name="evil", uid=0),
        _module_record(name="rootkit"),
        _listen_record(port=4444),
        _unit_record(unit="backdoor.service"),
    ]

    assert _detect(connection, current) == []


def test_global_disable_fires_nothing(tmp_path):
    """changes.enabled: false should suppress every category."""
    history = [_keys_record()]
    connection = _make_db(tmp_path, history)

    current = [_keys_record(path="/home/alice/.ssh/authorized_keys")]
    settings = ChangeSettings(enabled=False)

    assert _detect(connection, current, settings) == []


def test_unchanged_snapshot_fires_nothing(tmp_path):
    """Records identical to history should produce no findings."""
    history = [
        _cron_record(),
        _keys_record(),
        _profile_record(),
        _sudoers_record(),
        _user_record(),
        _module_record(),
        _listen_record(),
        _unit_record(),
    ]
    connection = _make_db(tmp_path, history)

    assert _detect(connection, history) == []


def test_new_systemd_unit_flagged(tmp_path):
    """A never-before-seen systemd unit should be flagged."""
    connection = _make_db(tmp_path, [_unit_record()])

    findings = _detect(connection, [_unit_record(unit="backdoor.service")])

    assert len(findings) == 1
    assert findings[0].finding_type == "host_change_new_systemd_unit"
    assert findings[0].severity == "medium"


def test_new_systemd_unit_from_tmp_escalated_to_high(tmp_path):
    """A new unit referencing a temp path should be high severity."""
    connection = _make_db(tmp_path, [_unit_record()])

    findings = _detect(
        connection,
        [_unit_record(unit="upd.service", description="/tmp/.upd --daemon")],
    )

    assert len(findings) == 1
    assert findings[0].finding_type == "host_change_new_systemd_unit"
    assert findings[0].severity == "high"


def test_new_cron_file_flagged_and_changed_detected(tmp_path):
    """New cron paths and changed cron content should both be flagged."""
    connection = _make_db(tmp_path, [_cron_record()])

    new_findings = _detect(connection, [_cron_record(path="/etc/cron.d/pwn")])
    assert [f.finding_type for f in new_findings] == ["host_change_new_cron_file"]
    assert new_findings[0].severity == "medium"

    connection = _make_db(tmp_path, [_cron_record()])
    changed_findings = _detect(
        connection, [_cron_record(content="* * * * * root /tmp/x\n")]
    )
    assert [f.finding_type for f in changed_findings] == [
        "host_change_cron_file_changed"
    ]


def test_new_and_changed_authorized_keys_flagged_high(tmp_path):
    """New and changed authorized_keys files should be high severity."""
    connection = _make_db(tmp_path, [_keys_record()])

    new_findings = _detect(
        connection, [_keys_record(path="/home/alice/.ssh/authorized_keys")]
    )
    assert [f.finding_type for f in new_findings] == [
        "host_change_new_authorized_keys"
    ]
    assert new_findings[0].severity == "high"

    connection = _make_db(tmp_path, [_keys_record()])
    changed_findings = _detect(
        connection, [_keys_record(content="ssh-ed25519 AAAA attacker\n")]
    )
    assert [f.finding_type for f in changed_findings] == [
        "host_change_authorized_keys_changed"
    ]
    assert changed_findings[0].severity == "high"


def test_new_and_changed_shell_profile_flagged_medium(tmp_path):
    """New and changed shell profiles should be medium severity."""
    connection = _make_db(tmp_path, [_profile_record()])

    new_findings = _detect(connection, [_profile_record(path="/etc/profile.d/evil.sh")])
    assert [f.finding_type for f in new_findings] == ["host_change_new_shell_profile"]
    assert new_findings[0].severity == "medium"

    connection = _make_db(tmp_path, [_profile_record()])
    changed_findings = _detect(
        connection, [_profile_record(content="export PATH=/tmp:$PATH\n")]
    )
    assert [f.finding_type for f in changed_findings] == [
        "host_change_shell_profile_changed"
    ]


def test_new_and_changed_sudoers_flagged_high(tmp_path):
    """New and changed sudoers files should be high severity."""
    connection = _make_db(tmp_path, [_sudoers_record()])

    new_findings = _detect(connection, [_sudoers_record(path="/etc/sudoers.d/evil")])
    assert [f.finding_type for f in new_findings] == ["host_change_new_sudoers"]
    assert new_findings[0].severity == "high"

    connection = _make_db(tmp_path, [_sudoers_record()])
    changed_findings = _detect(
        connection, [_sudoers_record(content="evil ALL=(ALL) NOPASSWD: ALL\n")]
    )
    assert [f.finding_type for f in changed_findings] == [
        "host_change_sudoers_changed"
    ]
    assert changed_findings[0].severity == "high"


def test_new_user_account_flagged(tmp_path):
    """A never-before-seen username should be flagged medium."""
    connection = _make_db(tmp_path, [_user_record()])

    findings = _detect(connection, [_user_record(name="alice", uid=1000)])

    assert [f.finding_type for f in findings] == ["host_change_new_user_account"]
    assert findings[0].severity == "medium"


def test_new_uid_zero_account_flagged_high(tmp_path):
    """A new non-root UID 0 account should be flagged high."""
    connection = _make_db(tmp_path, [_user_record()])

    findings = _detect(connection, [_user_record(name="toor", uid=0)])

    assert [f.finding_type for f in findings] == ["host_change_new_uid_zero_account"]
    assert findings[0].severity == "high"


def test_changed_user_account_flagged(tmp_path):
    """A modified known account (shell/uid/gid) should be flagged high."""
    connection = _make_db(tmp_path, [_user_record(name="alice", uid=1000)])

    findings = _detect(
        connection, [_user_record(name="alice", uid=1000, shell="/bin/sh")]
    )

    assert [f.finding_type for f in findings] == [
        "host_change_user_account_changed"
    ]
    assert findings[0].severity == "high"


def test_unchanged_user_account_fires_nothing(tmp_path):
    """An account identical to history should stay silent."""
    connection = _make_db(tmp_path, [_user_record(name="alice", uid=1000)])

    assert _detect(connection, [_user_record(name="alice", uid=1000)]) == []


def test_new_group_flagged(tmp_path):
    """A never-before-seen group should be flagged medium."""
    connection = _make_db(tmp_path, [_group_record()])

    findings = _detect(connection, [_group_record(name="docker")])

    assert [f.finding_type for f in findings] == ["host_change_new_group"]
    assert findings[0].severity == "medium"


def test_group_membership_change_flagged(tmp_path):
    """Added/removed members of a known group should be flagged."""
    connection = _make_db(tmp_path, [_group_record()])

    findings = _detect(connection, [_group_record(members=("root", "alice"))])

    assert [f.finding_type for f in findings] == ["host_change_group_changed"]
    assert findings[0].severity == "medium"


def test_unchanged_group_fires_nothing(tmp_path):
    """A group identical to history should stay silent."""
    connection = _make_db(tmp_path, [_group_record()])

    assert _detect(connection, [_group_record()]) == []


def test_new_kernel_module_flagged_and_ignorable(tmp_path):
    """Newly-seen kernel modules fire unless ignored by config."""
    connection = _make_db(tmp_path, [_module_record()])

    findings = _detect(connection, [_module_record(name="evilmod")])
    assert [f.finding_type for f in findings] == ["host_change_new_kernel_module"]
    assert findings[0].severity == "medium"

    connection = _make_db(tmp_path, [_module_record()])
    settings = ChangeSettings(ignored_kernel_modules=("evilmod",))
    assert _detect(connection, [_module_record(name="evilmod")], settings) == []


def test_new_listening_port_flagged_and_ignorable(tmp_path):
    """New listeners fire at low severity unless the port is ignored."""
    connection = _make_db(tmp_path, [_listen_record()])

    findings = _detect(connection, [_listen_record(port=4444)])
    assert [f.finding_type for f in findings] == ["host_change_new_listening_port"]
    assert findings[0].severity == "low"

    connection = _make_db(tmp_path, [_listen_record()])
    settings = ChangeSettings(ignored_listen_ports=(4444,))
    assert _detect(connection, [_listen_record(port=4444)], settings) == []


def test_category_toggles_suppress_findings(tmp_path):
    """Each per-category toggle should disable only its own findings."""
    history = [_keys_record(), _module_record()]
    connection = _make_db(tmp_path, history)

    current = [
        _keys_record(path="/home/alice/.ssh/authorized_keys"),
        _module_record(name="evilmod"),
    ]
    settings = ChangeSettings(authorized_keys=False)

    findings = _detect(connection, current, settings)

    assert [f.finding_type for f in findings] == ["host_change_new_kernel_module"]


def _autostart_record(
    path="/home/alice/.config/autostart/notes.desktop",
    content="[Desktop Entry]\nName=Notes\nExec=/usr/bin/notes\n",
    exec_line="/usr/bin/notes",
):
    return _make_record(
        "xdg_autostart_entry",
        {
            "path": path,
            "user": "alice",
            "name": "Notes",
            "exec": exec_line,
            "hidden": False,
            "content": content,
        },
        source="xdg_autostart",
    )


def _user_unit_record(
    path="/home/alice/.config/systemd/user/backup.timer",
    content="[Timer]\nOnCalendar=daily\n",
):
    return _make_record(
        "systemd_user_unit",
        {"path": path, "user": "alice", "link_target": None, "content": content},
        source="systemd_user_units",
    )


def _usb_record(
    name="046d:c52b:ABC123",
    classes=(),
    product="Unifying Receiver",
):
    return _make_record(
        "usb_device",
        {
            "name": name,
            "sysfs_name": "1-2",
            "vendor_id": "046d",
            "product_id": "c52b",
            "serial": "ABC123",
            "manufacturer": "Logitech",
            "product": product,
            "device_class": "00",
            "interface_classes": list(classes),
        },
        source="usb_devices",
    )


def _extension_record(
    name="alice:chrome:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    from_store=True,
    permissions=(),
    version="1.0",
):
    extension_id = name.rsplit(":", 1)[1]
    return _make_record(
        "browser_extension",
        {
            "name": name,
            "user": "alice",
            "browser": "chrome",
            "profile": "Default",
            "extension_id": extension_id,
            "display_name": "Example Extension",
            "version": version,
            "enabled": True,
            "from_store": from_store,
            "install_source": "webstore" if from_store else "sideloaded",
            "permissions": list(permissions),
            "path": f"/home/alice/.config/google-chrome/Default/Extensions/{extension_id}",
        },
        source="browser_extensions",
    )


def test_new_and_changed_xdg_autostart_entries_flagged(tmp_path):
    """New and changed autostart entries should be medium by default."""
    connection = _make_db(tmp_path / "new", [_autostart_record()])
    new_findings = _detect(
        connection,
        [_autostart_record(path="/home/alice/.config/autostart/evil.desktop")],
    )
    assert [f.finding_type for f in new_findings] == [
        "host_change_new_xdg_autostart_entry"
    ]
    assert new_findings[0].severity == "medium"

    connection = _make_db(tmp_path / "changed", [_autostart_record()])
    changed_findings = _detect(
        connection, [_autostart_record(content="[Desktop Entry]\nExec=/usr/bin/other\n")]
    )
    assert [f.finding_type for f in changed_findings] == [
        "host_change_xdg_autostart_entry_changed"
    ]
    assert changed_findings[0].severity == "medium"


def test_new_xdg_autostart_entry_from_tmp_escalated_to_high(tmp_path):
    """A new autostart entry executing from /tmp should escalate to high."""
    connection = _make_db(tmp_path, [_autostart_record()])

    findings = _detect(
        connection,
        [
            _autostart_record(
                path="/home/alice/.config/autostart/upd.desktop",
                content="[Desktop Entry]\nExec=/tmp/.upd --daemon\n",
                exec_line="/tmp/.upd --daemon",
            )
        ],
    )

    assert len(findings) == 1
    assert findings[0].finding_type == "host_change_new_xdg_autostart_entry"
    assert findings[0].severity == "high"
    assert findings[0].message.endswith("(references a temporary/writable path)")


def test_changed_xdg_autostart_entry_referencing_dev_shm_escalated(tmp_path):
    """A changed entry referencing /dev/shm should escalate to high."""
    connection = _make_db(tmp_path, [_autostart_record()])

    findings = _detect(
        connection,
        [
            _autostart_record(
                content="[Desktop Entry]\nExec=/dev/shm/.cache/run\n",
                exec_line="/dev/shm/.cache/run",
            )
        ],
    )

    assert len(findings) == 1
    assert findings[0].finding_type == "host_change_xdg_autostart_entry_changed"
    assert findings[0].severity == "high"
    assert "(references a temporary/writable path)" in findings[0].message


def test_new_and_changed_systemd_user_units_flagged(tmp_path):
    """New and changed user units should be medium by default."""
    connection = _make_db(tmp_path / "new", [_user_unit_record()])
    new_findings = _detect(
        connection,
        [_user_unit_record(path="/home/alice/.config/systemd/user/evil.service")],
    )
    assert [f.finding_type for f in new_findings] == [
        "host_change_new_systemd_user_unit"
    ]
    assert new_findings[0].severity == "medium"

    connection = _make_db(tmp_path / "changed", [_user_unit_record()])
    changed_findings = _detect(
        connection, [_user_unit_record(content="[Timer]\nOnCalendar=hourly\n")]
    )
    assert [f.finding_type for f in changed_findings] == [
        "host_change_systemd_user_unit_changed"
    ]
    assert changed_findings[0].severity == "medium"


def test_new_systemd_user_unit_from_var_tmp_escalated_to_high(tmp_path):
    """A new user unit referencing /var/tmp should escalate to high."""
    connection = _make_db(tmp_path, [_user_unit_record()])

    findings = _detect(
        connection,
        [
            _user_unit_record(
                path="/home/alice/.config/systemd/user/upd.service",
                content="[Service]\nExecStart=/var/tmp/.upd\n",
            )
        ],
    )

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].message.endswith("(references a temporary/writable path)")


def test_cron_and_shell_profile_tmp_references_not_escalated(tmp_path):
    """Categories without the escalate flag keep their base severity."""
    connection = _make_db(tmp_path / "cron", [_cron_record()])
    cron_findings = _detect(
        connection,
        [_cron_record(path="/etc/cron.d/pwn", content="* * * * * root /tmp/x\n")],
    )
    assert [f.finding_type for f in cron_findings] == ["host_change_new_cron_file"]
    assert cron_findings[0].severity == "medium"
    assert "temporary/writable path" not in cron_findings[0].message

    connection = _make_db(tmp_path / "profile", [_profile_record()])
    profile_findings = _detect(
        connection, [_profile_record(content="export PATH=/tmp/bin:$PATH\n")]
    )
    assert [f.finding_type for f in profile_findings] == [
        "host_change_shell_profile_changed"
    ]
    assert profile_findings[0].severity == "medium"
    assert "temporary/writable path" not in profile_findings[0].message


def test_usb_devices_empty_history_fires_nothing(tmp_path):
    """The first run baselines the USB inventory without findings."""
    connection = _make_db(tmp_path, [])

    assert _detect(connection, [_usb_record(classes=["03"])]) == []


def test_new_usb_hid_device_flagged_high(tmp_path):
    """A new device presenting a HID interface is the BadUSB pattern."""
    connection = _make_db(tmp_path, [_usb_record(name="1d6b:0002:usb1")])

    findings = _detect(connection, [_usb_record(classes=["03"])])

    assert [f.finding_type for f in findings] == ["host_change_new_usb_device"]
    assert findings[0].severity == "high"
    assert "HID" in findings[0].message
    assert "046d:c52b:ABC123" in findings[0].message


def test_new_usb_mass_storage_flagged_medium(tmp_path):
    """A new mass-storage device is medium severity."""
    connection = _make_db(tmp_path, [_usb_record(name="1d6b:0002:usb1")])

    findings = _detect(connection, [_usb_record(classes=["08"], product="Flash Drive")])

    assert [f.finding_type for f in findings] == ["host_change_new_usb_device"]
    assert findings[0].severity == "medium"
    assert "mass-storage" in findings[0].message


def test_new_usb_other_device_flagged_low(tmp_path):
    """A new device without HID/storage interfaces is low severity."""
    connection = _make_db(tmp_path, [_usb_record(name="1d6b:0002:usb1")])

    findings = _detect(connection, [_usb_record(classes=["02"])])

    assert [f.finding_type for f in findings] == ["host_change_new_usb_device"]
    assert findings[0].severity == "low"


def test_changed_usb_device_flagged_high_when_hid_appears(tmp_path):
    """A known device that grows a HID interface is high severity."""
    connection = _make_db(tmp_path, [_usb_record(classes=["08"])])

    findings = _detect(connection, [_usb_record(classes=["03", "08"])])

    assert [f.finding_type for f in findings] == ["host_change_usb_device_changed"]
    assert findings[0].severity == "high"


def test_changed_usb_device_without_hid_flagged_medium(tmp_path):
    """An identity change without HID involvement is medium severity."""
    connection = _make_db(tmp_path, [_usb_record()])

    findings = _detect(connection, [_usb_record(product="Different Product")])

    assert [f.finding_type for f in findings] == ["host_change_usb_device_changed"]
    assert findings[0].severity == "medium"


def test_usb_device_suppressed_via_ignore_list(tmp_path):
    """changes.ignored_usb_devices suppresses findings for that identity."""
    connection = _make_db(tmp_path, [_usb_record(name="1d6b:0002:usb1")])
    settings = ChangeSettings(ignored_usb_devices=("046d:c52b:ABC123",))

    assert _detect(connection, [_usb_record(classes=["03"])], settings) == []


def test_new_browser_extension_from_store_flagged_low(tmp_path):
    """A benign store-installed extension is low severity."""
    connection = _make_db(tmp_path, [_extension_record(name="alice:firefox:x@y.z")])

    findings = _detect(connection, [_extension_record()])

    assert [f.finding_type for f in findings] == [
        "host_change_new_browser_extension"
    ]
    assert findings[0].severity == "low"


def test_new_sideloaded_browser_extension_flagged_medium(tmp_path):
    """A sideloaded extension is medium with the reason in the message."""
    connection = _make_db(tmp_path, [_extension_record(name="alice:firefox:x@y.z")])

    findings = _detect(connection, [_extension_record(from_store=False)])

    assert [f.finding_type for f in findings] == [
        "host_change_new_browser_extension"
    ]
    assert findings[0].severity == "medium"
    assert "not installed from the vendor store" in findings[0].message


def test_new_browser_extension_with_high_risk_permissions_flagged_medium(tmp_path):
    """High-risk permissions make a new extension medium severity."""
    connection = _make_db(tmp_path, [_extension_record(name="alice:firefox:x@y.z")])

    findings = _detect(
        connection, [_extension_record(permissions=["nativeMessaging", "<all_urls>"])]
    )

    assert [f.finding_type for f in findings] == [
        "host_change_new_browser_extension"
    ]
    assert findings[0].severity == "medium"
    assert "high-risk permissions" in findings[0].message
    assert "nativeMessaging" in findings[0].message


def test_changed_browser_extension_flagged_low(tmp_path):
    """Changes to a known extension (version churn) are low severity."""
    connection = _make_db(tmp_path, [_extension_record()])

    findings = _detect(connection, [_extension_record(version="1.1")])

    assert [f.finding_type for f in findings] == [
        "host_change_browser_extension_changed"
    ]
    assert findings[0].severity == "low"


def test_browser_extension_suppressed_via_ignore_list(tmp_path):
    """changes.ignored_browser_extensions suppresses that extension."""
    connection = _make_db(tmp_path, [_extension_record(name="alice:firefox:x@y.z")])
    settings = ChangeSettings(
        ignored_browser_extensions=("alice:chrome:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",)
    )

    assert _detect(connection, [_extension_record()], settings) == []


def test_extension_risk_reasons():
    """Risk reasons cover sideloading and high-risk permissions only."""
    from traxerax_lite.change_detection import _extension_risk_reasons

    assert _extension_risk_reasons({"from_store": True, "permissions": ["tabs"]}) == []
    assert _extension_risk_reasons({"from_store": False, "permissions": []}) == [
        "not installed from the vendor store"
    ]
    reasons = _extension_risk_reasons(
        {"from_store": True, "permissions": ["debugger", "tabs", "proxy"]}
    )
    assert reasons == ["high-risk permissions: debugger, proxy"]
    reasons = _extension_risk_reasons(
        {"from_store": False, "permissions": ["*://*/*"]}
    )
    assert reasons == [
        "not installed from the vendor store",
        "high-risk permissions: *://*/*",
    ]


def test_new_category_toggles_suppress_their_findings(tmp_path):
    """The new per-category toggles disable only their own detectors."""
    history = [
        _autostart_record(),
        _user_unit_record(),
        _usb_record(name="1d6b:0002:usb1"),
        _extension_record(name="alice:firefox:x@y.z"),
    ]
    current = [
        _autostart_record(path="/home/alice/.config/autostart/evil.desktop"),
        _user_unit_record(path="/home/alice/.config/systemd/user/evil.service"),
        _usb_record(),
        _extension_record(),
    ]

    connection = _make_db(tmp_path / "all-on", history)
    enabled_findings = _detect(connection, current)
    assert {f.finding_type for f in enabled_findings} == {
        "host_change_new_xdg_autostart_entry",
        "host_change_new_systemd_user_unit",
        "host_change_new_usb_device",
        "host_change_new_browser_extension",
    }

    connection = _make_db(tmp_path / "all-off", history)
    settings = ChangeSettings(
        xdg_autostart=False,
        systemd_user_units=False,
        usb_devices=False,
        browser_extensions=False,
    )
    assert _detect(connection, current, settings) == []
