"""Suppression and baselining helpers."""

from __future__ import annotations

import ipaddress

from traxerax_lite.config import BaselineSettings
from traxerax_lite.models import EnforcementAction, Event


def should_suppress_event(
    event: Event,
    settings: BaselineSettings,
) -> bool:
    """Return True when an event matches configured suppression rules."""
    if _ip_is_suppressed(event.src_ip, settings):
        return True

    if event.username and event.username in settings.ignored_usernames:
        return True

    if event.normalized_path and event.normalized_path in settings.ignored_nginx_paths:
        return True

    if event.path and event.path.rstrip("/") in settings.ignored_nginx_paths:
        return True

    if event.user_agent:
        for pattern in settings.ignored_user_agent_patterns:
            if pattern.search(event.user_agent):
                return True

    return False


def should_suppress_action(
    action: EnforcementAction,
    settings: BaselineSettings,
) -> bool:
    """Return True when an enforcement action matches suppression rules."""
    return _ip_is_suppressed(action.src_ip, settings)


def _ip_is_suppressed(
    src_ip: str | None,
    settings: BaselineSettings,
) -> bool:
    """Return True when an IP matches exact or CIDR suppression."""
    if src_ip is None:
        return False

    if src_ip in settings.ignored_source_ips:
        return True

    try:
        ip = ipaddress.ip_address(src_ip)
    except ValueError:
        return False

    for cidr in settings.ignored_source_cidrs:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue

    return False
