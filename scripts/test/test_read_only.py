"""Verify that configured panel probes cannot leave the selected stand."""
import unittest
from unittest.mock import patch
import read_only


class LocalPanelTests(unittest.TestCase):
    """Check URL and assigned-address guards without making any HTTP request."""

    def test_foreign_address_rejected(self):
        """An address outside the stand is rejected before any HTTP probe."""
        with patch.object(read_only.subprocess, 'check_output', return_value='[]'):
            with self.assertRaisesRegex(ValueError, 'not assigned'):
                read_only.local_origin('http://192.0.2.7:8080')

    def test_assigned_address_allowed(self):
        """A configured address genuinely assigned to the chosen stand is supported."""
        with patch.object(read_only.subprocess, 'check_output', return_value='[{"addr_info":[{"local":"192.0.2.7"}]}]'):
            self.assertEqual(read_only.local_origin('http://192.0.2.7:8080'), 'http://192.0.2.7:8080')

    def test_loopback_requires_no_network_discovery(self):
        """Loopback URLs are validated locally without DNS or interface commands."""
        with patch.object(read_only.subprocess, 'check_output') as command:
            self.assertEqual(read_only.local_origin('http://[::1]:8080/'), 'http://[::1]:8080')
            command.assert_not_called()

    def test_credentials_path_and_dns_refused(self):
        """Untrusted URLs cannot introduce credentials, path injection or DNS resolution."""
        for value in ('http://user@127.0.0.1:8080', 'http://127.0.0.1/a', 'http://example.com', 'https://127.0.0.1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                read_only.local_origin(value)


if __name__ == '__main__':
    unittest.main()
