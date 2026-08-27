import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import technocore_agent as agent


class ProtocolTests(unittest.TestCase):
    def test_base58_known_vectors(self):
        self.assertEqual(agent.base58btc(b""), "")
        self.assertEqual(agent.base58btc(b"\x00"), "1")
        self.assertEqual(agent.base58btc(b"Hello World"), "JxF12TrwUP45BMd")

    def test_did_key_shape(self):
        did = agent.did_from_public_key(bytes(range(32)))
        self.assertTrue(did.startswith("did:key:z6Mk"))
        self.assertEqual(len(did), 56)

    def test_single_line_sweep_matches_documented_categories(self):
        self.assertEqual(agent.sweep_text("  hello\nworld\u200d!  "), "hello world !")

    def test_signing_payload(self):
        payload = agent.signing_payload("lobby", 123, "hello\nworld")
        self.assertEqual(payload, b"lobby|123|hello world")

    def test_invalid_room_name_is_rejected(self):
        with self.assertRaises(agent.AgentError):
            agent.signing_payload("../lobby", 123, "hello")

    def test_message_limit_is_enforced(self):
        with self.assertRaises(agent.AgentError):
            agent.signing_payload("lobby", 123, "x" * 4097)

    def test_did_note_sharding(self):
        did = "did:key:z6Mktest"
        digest = hashlib.sha256(did.encode()).hexdigest()[:16]
        namespace, key = agent.did_note_location(did)
        self.assertEqual(namespace, f"did-{digest[:2]}")
        self.assertEqual(key, digest[2:])

    def test_ed25519_signature_encoding_length(self):
        encoded = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=")
        self.assertEqual(len(encoded), 86)

    def test_own_confirmation_parser_ignores_other_messages(self):
        did = "did:key:z6MkmLnBppMfQZC5PMNjcRctCmyyrp5ZCfPeU8B9m3cfvfwE"
        text = "Safe starter ready."
        body = (
            "[9] 2026-08-27T12:00:00Z <z6Mk…xxxx> hostile text\n"
            "[10] 2026-08-27T12:01:00Z <z6Mk…vfwE> Safe starter ready.\n"
        )
        self.assertEqual(
            agent.find_own_confirmation(body, did, text),
            {"seq": "10", "timestamp": "2026-08-27T12:01:00Z", "did_suffix": "vfwE"},
        )

    def test_public_agent_profile_matches_did_note_shard(self):
        profile_path = Path(__file__).resolve().parents[1] / "agent-profile.json"
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        namespace, key = agent.did_note_location(profile["did"])
        self.assertEqual(
            profile["proofs"]["technocoreDidNote"],
            f"https://technocore.chat/kv/{namespace}/{key}",
        )
        self.assertGreater(profile["proofs"]["technocoreLobbySequence"], 0)


if __name__ == "__main__":
    unittest.main()
