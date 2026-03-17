"""
Bug Condition Exploration Test — Property 1: Telnet Line-Password Username Not Suppressed

**Validates: Requirements 1.1, 1.2, 1.3**

CRITICAL: This test is EXPECTED TO FAIL on unfixed code.
Failure confirms the bug exists: `username` is passed non-empty to ConnectHandler
on cisco_ios_telnet paths.

Three call sites are tested:
1. test_authentication — local_test_password retry (src/utils/auth_test.py)
2. _test_local_login   (src/actions/update_aaa_login_method.py)
3. _test_local_show_run (src/actions/update_aaa_login_method.py)
"""

import pytest
from unittest.mock import patch, MagicMock, call


# ---------------------------------------------------------------------------
# Helper: a mock ConnectHandler that raises when username is non-empty
# and device_type is cisco_ios_telnet — simulating the real device behaviour.
# ---------------------------------------------------------------------------

def _telnet_username_guard(**kwargs):
    """
    Raise the real-world error when a non-empty username is sent to a
    cisco_ios_telnet device that only presents a Password: prompt.
    """
    if kwargs.get("device_type") == "cisco_ios_telnet" and kwargs.get("username", "") != "":
        raise Exception("telnet connection closed")
    # For any other call, return a mock connection object
    mock_conn = MagicMock()
    mock_conn.enable.return_value = None
    mock_conn.send_command.return_value = "hostname router\nversion 15.1\n" + "x" * 100
    mock_conn.disconnect.return_value = None
    return mock_conn


# ---------------------------------------------------------------------------
# Call site 2: _test_local_login
# ---------------------------------------------------------------------------

class TestBugCondition_TestLocalLogin:
    """
    Verify that _test_local_login passes username="admin" (non-empty) to
    ConnectHandler when device_type="cisco_ios_telnet" on unfixed code.

    On unfixed code: ConnectHandler is called with username="admin"
    -> _telnet_username_guard raises Exception("telnet connection closed")
    -> _test_local_login returns (False, ...) containing the error message
    -> The assertion below FAILS because we expect success=True but get False.

    This FAILURE is the SUCCESS condition for this exploration test.
    """

    @pytest.mark.parametrize("username", ["admin", "cisco", "netops"])
    def test_telnet_login_passes_nonempty_username(self, username):
        """
        Bug condition: _test_local_login with cisco_ios_telnet and non-empty
        username should succeed (after fix). On unfixed code it fails because
        ConnectHandler receives username != "" and the device drops the connection.

        EXPECTED TO FAIL on unfixed code — failure proves the bug exists.
        """
        from src.actions.update_aaa_login_method import _test_local_login

        with patch(
            "src.actions.update_aaa_login_method.ConnectHandler",
            side_effect=_telnet_username_guard,
        ) as mock_ch:
            success, message = _test_local_login(
                host_name="router-01",
                ip="192.168.1.1",
                port=23,
                device_type="cisco_ios_telnet",
                username=username,
                local_password="localpass123",
                enable_secret="localpass123",
            )

        # On FIXED code: ConnectHandler is called with username="" so the guard
        # does NOT raise, and success=True.
        # On UNFIXED code: ConnectHandler is called with username=username (non-empty),
        # the guard raises, and success=False — this assertion FAILS, proving the bug.
        assert success is True, (
            f"BUG CONFIRMED: _test_local_login called ConnectHandler with "
            f"username={username!r} (non-empty) for cisco_ios_telnet. "
            f"Got: success={success}, message={message!r}. "
            f"ConnectHandler calls: {mock_ch.call_args_list}"
        )


# ---------------------------------------------------------------------------
# Call site 3: _test_local_show_run
# ---------------------------------------------------------------------------

class TestBugCondition_TestLocalShowRun:
    """
    Verify that _test_local_show_run passes username="admin" (non-empty) to
    ConnectHandler when device_type="cisco_ios_telnet" on unfixed code.
    """

    @pytest.mark.parametrize("username", ["admin", "cisco", "netops"])
    def test_telnet_show_run_passes_nonempty_username(self, username):
        """
        Bug condition: _test_local_show_run with cisco_ios_telnet and non-empty
        username should succeed (after fix). On unfixed code it fails.

        EXPECTED TO FAIL on unfixed code — failure proves the bug exists.
        """
        from src.actions.update_aaa_login_method import _test_local_show_run

        with patch(
            "src.actions.update_aaa_login_method.ConnectHandler",
            side_effect=_telnet_username_guard,
        ) as mock_ch:
            success, message = _test_local_show_run(
                host_name="router-01",
                ip="192.168.1.1",
                port=23,
                device_type="cisco_ios_telnet",
                username=username,
                local_password="localpass123",
                enable_secret="localpass123",
            )

        # On FIXED code: success=True (username="" passed to ConnectHandler).
        # On UNFIXED code: success=False (username=username passed) — assertion FAILS.
        assert success is True, (
            f"BUG CONFIRMED: _test_local_show_run called ConnectHandler with "
            f"username={username!r} (non-empty) for cisco_ios_telnet. "
            f"Got: success={success}, message={message!r}. "
            f"ConnectHandler calls: {mock_ch.call_args_list}"
        )


# ---------------------------------------------------------------------------
# Call site 1: test_authentication — local_test_password retry
# ---------------------------------------------------------------------------

class TestBugCondition_TestAuthentication:
    """
    Verify that the local_test_password retry in test_authentication passes a
    non-empty username to the underlying Netmiko connection for cisco_ios_telnet.

    Setup:
    - Host has device_type=cisco_ios_telnet, username="admin"
    - Primary auth fails (test_single_device returns failed=True)
    - local_test_password is set in host data
    - The retry should (after fix) clear host_obj.username to ""
    - On unfixed code, host_obj.username remains "admin" -> Netmiko gets non-empty username
    """

    def _make_nornir_mock(self, host_name, ip, username, device_type, port, local_test_password):
        """Build a minimal Nornir mock with one host configured for cisco_ios_telnet."""
        # Connection options mock
        conn_opts = MagicMock()
        conn_opts.port = port
        conn_opts.extras = {"device_type": device_type, "secret": ""}

        # Host mock
        host_obj = MagicMock()
        host_obj.name = host_name
        host_obj.hostname = ip
        host_obj.username = username
        host_obj.password = "tacacs_password"
        host_obj.platform = "cisco_ios"  # nornir platform (not netmiko device_type)
        host_obj.data = {"local_test_password": local_test_password, "enable_secret": ""}
        host_obj.connection_options = {"netmiko": conn_opts}

        # Inventory mock
        inventory = MagicMock()
        inventory.hosts = {host_name: host_obj}

        # nr mock
        nr = MagicMock()
        nr.inventory = inventory

        return nr, host_obj, conn_opts

    def test_telnet_retry_passes_nonempty_username(self):
        """
        Bug condition: after primary auth fails on a cisco_ios_telnet host with
        local_test_password set, the retry should use username="" (after fix).
        On unfixed code, host_obj.username is NOT cleared, so the retry still
        carries the original non-empty username.

        We detect this by checking host_obj.username after the retry setup
        (before test_single_device is called the second time).

        EXPECTED TO FAIL on unfixed code — failure proves the bug exists.
        """
        from src.utils.auth_test import test_authentication

        host_name = "router-01"
        ip = "192.168.1.1"
        username = "admin"
        device_type = "cisco_ios_telnet"
        port = 23
        local_test_password = "localpass123"

        nr, host_obj, conn_opts = self._make_nornir_mock(
            host_name, ip, username, device_type, port, local_test_password
        )

        # Primary auth result: failed
        primary_result_data = {"success": False, "error": "Authentication failed", "ssh_banner_error": False}
        primary_host_result = MagicMock()
        primary_host_result.failed = True
        primary_host_result.result = primary_result_data

        primary_run_result = {host_name: [primary_host_result]}

        # Retry auth result: success (so test_authentication proceeds past the retry)
        retry_result_data = {"success": True, "message": "ok"}
        retry_host_result = MagicMock()
        retry_host_result.failed = False
        retry_host_result.result = retry_result_data

        retry_run_result = {host_name: [retry_host_result]}

        # nr.filter() returns a sub-nr whose .run() returns the appropriate result
        primary_sub_nr = MagicMock()
        primary_sub_nr.run.return_value = primary_run_result

        retry_sub_nr = MagicMock()
        retry_sub_nr.run.return_value = retry_run_result

        # First filter call -> primary, second -> retry
        nr.filter.side_effect = [primary_sub_nr, retry_sub_nr]

        # is_reachable: device is reachable
        with patch("src.utils.auth_test.is_reachable", return_value=True):
            test_authentication(nr, max_attempts=1)

        # After the retry setup block runs, host_obj.username should be ""
        # (on fixed code). On unfixed code it remains "admin".
        assert host_obj.username == "", (
            f"BUG CONFIRMED: test_authentication did NOT clear host_obj.username "
            f"before the local_test_password retry on cisco_ios_telnet. "
            f"host_obj.username={host_obj.username!r} (expected '' after fix). "
            f"This means ConnectHandler will receive username='admin' and the "
            f"device will drop the Telnet connection."
        )
