# src/utils/test_tacacs_fallback.py
"""
Bug condition exploration tests for TACACS local auth fallback.

These tests encode the EXPECTED (fixed) behavior.
They MUST FAIL on unfixed code — failure confirms the bug exists.
DO NOT fix the code or the tests when they fail.
"""
from __future__ import absolute_import
import sys
import os
import unittest
from unittest.mock import MagicMock, patch, call

# Ensure project src is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))


class TestBugConditionExploration(unittest.TestCase):

    def _make_task(self):
        """Build a minimal mock task for enter_enable_mode_robust."""
        task = MagicMock()
        task.host.name = "test-device"
        task.host.data = {"enable_secret": "secret123"}
        task.host.data.get = task.host.data.get  # use real dict .get
        task.nornir.config = MagicMock()
        return task

    def test_bug_condition_enter_enable_mode_robust_no_sleep_on_tacacs_rejection(self):
        """
        BUG CONDITION: When get_connection() raises 'telnet connection closed',
        enter_enable_mode_robust should NOT call time.sleep (expected fixed behavior).

        EXPECTED OUTCOME: FAILS on unfixed code because sleep IS called 2 times.
        This failure proves the bug exists.

        Validates: Requirements 1.1, 1.2, 1.3
        """
        from nornir_network_configurator.src.utils.enable_mode import enter_enable_mode_robust

        task = self._make_task()
        # Always raise "telnet connection closed" on get_connection
        task.host.get_connection.side_effect = Exception("telnet connection closed")

        with patch('nornir_network_configurator.src.utils.enable_mode.time.sleep') as mock_sleep:
            success, message = enter_enable_mode_robust(
                task=task,
                max_attempts=3,
                delay_between_attempts=15,
                force_new_connection=False
            )

        # Expected (fixed) behavior: detect TACACS rejection on first attempt,
        # return immediately — sleep should NOT be called at all.
        # On unfixed code: sleep IS called 2 times (between attempts 1→2 and 2→3).
        sleep_call_count = mock_sleep.call_count
        self.assertFalse(
            success,
            "enter_enable_mode_robust should return failure on TACACS rejection"
        )
        self.assertIn(
            "telnet connection closed",
            message.lower(),
            "Failure message should reference the connection error"
        )
        self.assertEqual(
            0,
            sleep_call_count,
            "BUG: time.sleep was called {} time(s) — wasted ~{}s on retries after "
            "TACACS rejection. Expected 0 sleep calls (immediate return).".format(
                sleep_call_count, sleep_call_count * 15
            )
        )

    def test_bug_condition_run_no_unconditional_fallback_on_tacacs_rejection(self):
        """
        BUG CONDITION: When enter_enable_mode_robust returns (False, "telnet connection closed")
        and local_test_password is set, run() should NOT call enter_enable_mode_robust a second
        time unconditionally (expected fixed behavior: only retry on tacacs_rejection signal).

        EXPECTED OUTCOME: FAILS on unfixed code because the current code DOES call
        enter_enable_mode_robust a second time unconditionally.
        This failure proves the bug exists.

        Validates: Requirements 1.2, 1.3
        """
        from nornir_network_configurator.src.actions import update_aaa_login_method

        # Build a mock task with local_test_password set
        task = MagicMock()
        task.host.name = "test-device"
        task.host.platform = "cisco_ios"
        task.host.hostname = "192.168.1.1"
        task.host.username = "admin"
        task.host.data = {
            "local_test_password": "localpass",
            "enable_secret": "secret123",
        }
        task.host.get = MagicMock(return_value="N/A")
        task.host.connection_options = {}

        enable_mock = MagicMock(
            return_value=(False, "telnet connection closed")
        )

        with patch.object(update_aaa_login_method, 'enter_enable_mode_robust', enable_mock):
            with patch.object(update_aaa_login_method, '_load_enable_secret',
                              return_value="secret123"):
                with patch.object(update_aaa_login_method, '_load_aaa_commands',
                                  return_value=["aaa authentication login default local"]):
                    result = update_aaa_login_method.run(task=task)

        result_data = result.result

        # Expected (fixed) behavior: when the signal is NOT "tacacs_rejection" (just a raw
        # error string), run() should mark FAIL without a second enter_enable_mode_robust call.
        # On unfixed code: the code calls enter_enable_mode_robust a SECOND time
        # unconditionally (the "device may already be updated" fallback block).
        enable_call_count = enable_mock.call_count
        self.assertEqual(
            "FAIL",
            result_data.get("status"),
            "run() should return status=FAIL when enable mode fails with TACACS rejection"
        )
        self.assertEqual(
            1,
            enable_call_count,
            "BUG: enter_enable_mode_robust was called {} time(s). Expected exactly 1 call "
            "(no unconditional fallback). The second call wastes time and bypasses "
            "signal-based routing.".format(enable_call_count)
        )


if __name__ == '__main__':
    unittest.main()
