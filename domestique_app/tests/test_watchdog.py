"""Tests for the proxy watchdog service."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from domestique_app.services.watchdog import (
    ProtectionState,
    Watchdog,
    WatchdogConfig,
)


@pytest.fixture
def watchdog_config():
    """Fast-polling config for tests."""
    config = WatchdogConfig()
    config.POLL_INTERVAL = 0.2
    config.BACKOFF_BASE = 1.0
    config.BACKOFF_MAX = 2.0
    config.MAX_RESTART_ATTEMPTS = 3
    return config


class TestWatchdogLifecycle:
    """Test watchdog start/stop lifecycle."""

    def test_initial_state_is_stopped(self, watchdog_config):
        wd = Watchdog(restart_proxy=MagicMock(), config=watchdog_config)
        assert wd.state == ProtectionState.STOPPED

    def test_start_sets_starting_state(self, watchdog_config):
        wd = Watchdog(restart_proxy=MagicMock(), config=watchdog_config)
        wd.start()
        assert wd.state == ProtectionState.STARTING
        wd.stop()

    def test_stop_sets_stopped_state(self, watchdog_config):
        wd = Watchdog(restart_proxy=MagicMock(), config=watchdog_config)
        wd.start()
        wd.stop()
        assert wd.state == ProtectionState.STOPPED

    def test_start_is_idempotent(self, watchdog_config):
        wd = Watchdog(restart_proxy=MagicMock(), config=watchdog_config)
        wd.start()
        wd.start()  # Should not create second thread
        wd.stop()


class TestWatchdogHealthChecks:
    """Test health check logic."""

    @patch("domestique_app.services.watchdog.is_port_listening")
    def test_healthy_state_when_both_ok(self, mock_port, watchdog_config):
        """When PAC and proxy are healthy, state should be ACTIVE."""
        mock_port.return_value = True

        wd = Watchdog(restart_proxy=MagicMock(), config=watchdog_config)
        assert wd._is_proxy_healthy()

    @patch("urllib.request.build_opener")
    def test_pac_server_healthy(self, mock_build_opener, watchdog_config):
        """PAC server health check returns True when responsive."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        mock_build_opener.return_value = mock_opener

        wd = Watchdog(restart_proxy=MagicMock(), config=watchdog_config)
        assert wd._is_pac_server_healthy()

    @patch("domestique_app.services.watchdog.is_port_listening")
    def test_unhealthy_when_proxy_not_listening(self, mock_port, watchdog_config):
        """When proxy port has no listener, should report unhealthy."""
        mock_port.return_value = False
        wd = Watchdog(restart_proxy=MagicMock(), config=watchdog_config)
        assert not wd._is_proxy_healthy()


class TestWatchdogRecovery:
    """Test automatic recovery behavior."""

    def test_restart_called_on_failure(self, watchdog_config):
        """Watchdog should attempt to restart proxy on detection of failure."""
        restart_mock = MagicMock(return_value=True)
        wd = Watchdog(restart_proxy=restart_mock, config=watchdog_config)

        # Simulate a failed state requiring recovery
        wd._state = ProtectionState.ACTIVE
        wd._attempt_recovery()

        restart_mock.assert_called_once()

    def test_backoff_prevents_rapid_restarts(self, watchdog_config):
        """Consecutive restarts should be throttled by backoff."""
        restart_mock = MagicMock(return_value=False)
        wd = Watchdog(restart_proxy=restart_mock, config=watchdog_config)

        # First attempt should work
        wd._attempt_recovery()
        assert restart_mock.call_count == 1

        # Immediate second attempt should be throttled
        wd._attempt_recovery()
        assert restart_mock.call_count == 1  # Not called again due to backoff

    def test_max_attempts_enters_failed_state(self, watchdog_config):
        """After max restarts, watchdog should enter FAILED state."""
        state_changes = []
        restart_mock = MagicMock(return_value=False)

        def on_state(state):
            state_changes.append(state)

        wd = Watchdog(
            restart_proxy=restart_mock,
            on_state_change=on_state,
            config=watchdog_config,
        )

        # Exhaust all attempts
        wd._restart_count = watchdog_config.MAX_RESTART_ATTEMPTS
        wd._attempt_recovery()

        assert wd.state == ProtectionState.FAILED

    def test_reset_backoff_clears_counter(self, watchdog_config):
        wd = Watchdog(restart_proxy=MagicMock(), config=watchdog_config)
        wd._restart_count = 5
        wd.reset_backoff()
        assert wd._restart_count == 0


class TestNetworkChangeDetection:
    """Test network interface change detection."""

    @patch("domestique_app.services.watchdog.Watchdog._get_active_interfaces")
    @patch("domestique_app.services.watchdog.Watchdog._reapply_pac")
    def test_reapply_on_new_interface(self, mock_reapply, mock_ifaces, watchdog_config):
        """Should re-apply PAC when a new interface appears."""
        wd = Watchdog(restart_proxy=MagicMock(), config=watchdog_config)
        wd._known_interfaces = {"Wi-Fi"}

        mock_ifaces.return_value = ["Wi-Fi", "Ethernet"]
        wd._check_network_changes()

        mock_reapply.assert_called_once()
        assert "Ethernet" in wd._known_interfaces

    @patch("domestique_app.services.watchdog.Watchdog._get_active_interfaces")
    @patch("domestique_app.services.watchdog.Watchdog._reapply_pac")
    def test_no_reapply_when_stable(self, mock_reapply, mock_ifaces, watchdog_config):
        """Should not re-apply PAC when interfaces haven't changed."""
        wd = Watchdog(restart_proxy=MagicMock(), config=watchdog_config)
        wd._known_interfaces = {"Wi-Fi"}

        mock_ifaces.return_value = ["Wi-Fi"]
        wd._check_network_changes()

        mock_reapply.assert_not_called()


class TestStateChangeCallback:
    """Test state change notifications."""

    def test_callback_called_on_state_change(self, watchdog_config):
        states = []
        wd = Watchdog(
            restart_proxy=MagicMock(),
            on_state_change=lambda s: states.append(s),
            config=watchdog_config,
        )

        wd._set_state(ProtectionState.ACTIVE)
        wd._set_state(ProtectionState.DEGRADED)

        assert states == [ProtectionState.ACTIVE, ProtectionState.DEGRADED]

    def test_no_callback_on_same_state(self, watchdog_config):
        states = []
        wd = Watchdog(
            restart_proxy=MagicMock(),
            on_state_change=lambda s: states.append(s),
            config=watchdog_config,
        )

        wd._set_state(ProtectionState.ACTIVE)
        wd._set_state(ProtectionState.ACTIVE)  # Same state

        assert len(states) == 1


class TestPACSubdomainMatching:
    """Test that PAC handles subdomains correctly."""

    def test_pac_includes_subdomain_matching(self):
        from domestique_app.services.interceptor import generate_pac_file

        pac_path = generate_pac_file()
        content = pac_path.read_text()

        # Should have both exact match and subdomain match
        assert 'host === "api.openai.com"' in content
        assert 'dnsDomainIs(host, ".api.openai.com")' in content

    def test_pac_returns_proxy_for_known_domains(self):
        from domestique_app.services.interceptor import generate_pac_file

        pac_path = generate_pac_file()
        content = pac_path.read_text()

        # Verify structure
        assert "function FindProxyForURL" in content
        assert "PROXY 127.0.0.1:8080" in content
        assert 'return "DIRECT"' in content
