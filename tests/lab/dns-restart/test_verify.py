"""Fault injections for the offline capture auditor without opening any network sockets."""

import unittest
from pathlib import Path
from unittest.mock import patch

from verify import RU_A, audit_ru


class AuditTests(unittest.TestCase):
    """Detect an unrelated RU attempt even with no peer response or after a client timeout."""

    def test_unmarked_packets_across_the_entire_capture(self):
        """Allow the expected transaction and catch a later reused TCP tuple and an unmarked UDP datagram."""
        conn = (b"10.85.1.1", b"44000", RU_A.encode(), b"19091")
        permit = {
            "start": 100,
            "wall": 110,
            "name": "hot.lab.test",
            "proto": "tcp",
            "token": "client-allowed",
            "reply": {"group": "ru", "ip": RU_A},
        }
        data = [(108, conn, b"proto TCP ... client-allowed")]
        syn = (102, conn, b"proto TCP ... SYN")
        with patch("verify.packet_rows", side_effect=[data, [syn]]):
            errors, earliest = audit_ru(Path("/unused"), 60, [permit])
            self.assertEqual(errors, [])
            self.assertEqual(earliest, {"client-allowed": 102})
        # Identical socket tuple is insufficient evidence after the authorized flow ended.
        with patch(
            "verify.packet_rows",
            side_effect=[
                data,
                [
                    syn,
                    (160, conn, b"proto TCP ... SYN"),
                    (161, conn, b"proto UDP ... unrelated"),
                ],
            ],
        ):
            errors, _ = audit_ru(Path("/unused"), 60, [permit])
            self.assertEqual(len(errors), 2)
            self.assertIn("160", errors[0])
            self.assertIn("161", errors[1])

    def test_explicit_fi_token_cannot_whitelist_a_ru_attempt(self):
        """A real peer receipt for a forbidden FI flow still produces a safety failure."""
        conn = (b"10.85.1.1", b"44001", RU_A.encode(), b"19091")
        row = {
            "start": 100,
            "wall": 110,
            "name": "first.only-fi.lab.test",
            "proto": "udp",
            "token": "forbidden",
            "reply": {"group": "ru", "ip": RU_A},
        }
        datagram = (105, conn, b"proto UDP ... forbidden")
        with patch("verify.packet_rows", side_effect=[[datagram], [datagram]]):
            errors, earliest = audit_ru(Path("/unused"), 60, [row])
            self.assertEqual(len(errors), 1)
            self.assertFalse(earliest)
