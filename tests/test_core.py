"""Security-focused tests using synthetic secrets only."""

import copy
import json
import unittest
from urllib.parse import parse_qsl, urlsplit

from logshare_guard.core import redact


MARKER = "[REDACTED]"
RULES = {
    "sensitive_key",
    "named_value",
    "url_userinfo",
    "url_query",
    "url_fragment",
    "invalid_url",
}


class RedactTests(unittest.TestCase):
    def assert_safe_stats(self, stats):
        self.assertIsInstance(stats, dict)
        self.assertTrue(set(stats).issubset(RULES), stats)
        for count in stats.values():
            self.assertIs(type(count), int)
            self.assertGreater(count, 0)

    def test_secret_keys_are_normalized_and_public_fields_survive(self):
        source = {
            "Password": "synthetic-password",
            "API_KEY": "synthetic-api-key",
            "access-token": "synthetic-access-token",
            "clientSecret": "synthetic-client-secret",
            "Authorization": "Bearer synthetic-bearer-token",
            "Cookie": "session=synthetic-cookie",
            "status": "OPERATING",
            "wait_time": 15,
            "timestamp": "2026-10-10T10:00:00Z",
        }
        result, stats = redact(source)
        for key in list(source)[:6]:
            self.assertEqual(result[key], MARKER)
        for key in ("status", "wait_time", "timestamp"):
            self.assertEqual(result[key], source[key])
        self.assertEqual(stats, {"sensitive_key": 6})

    def test_nested_arrays_and_secret_containers(self):
        source = {
            "events": [
                {"password": {"raw": "synthetic-nested-secret"}, "id": 1},
                [{"api_key": ["synthetic-secret-one", "synthetic-secret-two"]}],
                None,
                False,
                0,
            ]
        }
        result, stats = redact(source)
        self.assertEqual(
            result,
            {"events": [{"password": MARKER, "id": 1}, [{"api_key": MARKER}], None, False, 0]},
        )
        self.assertEqual(stats, {"sensitive_key": 2})
        self.assertNotIn("synthetic-secret", json.dumps(result))

    def test_input_is_unchanged_and_output_does_not_alias_it(self):
        source = {"events": [{"password": "synthetic-password", "tags": ["public"]}]}
        original = copy.deepcopy(source)
        result, _ = redact(source)
        self.assertEqual(source, original)
        result["events"][0]["tags"].append("another")
        self.assertEqual(source, original)

    def test_name_value_records_redact_only_the_secret_value(self):
        source = [
            {"name": "Authorization", "value": "Bearer synthetic-token", "note": "public"},
            {"name": "Cookie", "value": "session=synthetic-session"},
            {"name": "Content-Type", "value": "application/json"},
        ]
        result, stats = redact(source)
        self.assertEqual(result[0], {"name": "Authorization", "value": MARKER, "note": "public"})
        self.assertEqual(result[1], {"name": "Cookie", "value": MARKER})
        self.assertEqual(result[2], source[2])
        self.assertEqual(stats, {"named_value": 2})

    def test_name_value_field_spelling_is_normalized(self):
        result, stats = redact({"NAME": "API-KEY", "VALUE": "synthetic-api-key"})
        self.assertEqual(result, {"NAME": "API-KEY", "VALUE": MARKER})
        self.assertEqual(stats, {"named_value": 1})

    def test_unrelated_name_value_records_remain_unchanged(self):
        for source in (
            {"name": 42, "value": "public"},
            {"name": None, "value": "public"},
            {"name": {"label": "public"}, "value": "public"},
            {"name": "Authorization", "description": "No value provided"},
        ):
            with self.subTest(source=source):
                result, stats = redact(source)
                self.assertEqual(result, source)
                self.assertEqual(stats, {})

    def test_extra_keys_cover_objects_name_value_records_and_urls(self):
        source = {
            "Tenant-Secret-Code": "synthetic-object-secret",
            "headers": [{"name": "tenant_secret_code", "value": "synthetic-header-secret"}],
            "url": "https://example.test/path?tenantSecretCode=synthetic-url-secret&view=public",
        }
        result, stats = redact(source, extra_keys=("tenant_secret_code",))
        self.assertEqual(result["Tenant-Secret-Code"], MARKER)
        self.assertEqual(result["headers"][0]["value"], MARKER)
        self.assertEqual(
            parse_qsl(urlsplit(result["url"]).query),
            [("tenantSecretCode", MARKER), ("view", "public")],
        )
        self.assertEqual(stats, {"sensitive_key": 1, "named_value": 1, "url_query": 1})

    def test_extra_keys_do_not_persist_between_calls(self):
        source = {"tenant_code": "public-without-custom-policy"}
        redact(source, extra_keys=("tenant_code",))
        result, stats = redact(source)
        self.assertEqual(result, source)
        self.assertEqual(stats, {})

    def test_url_credentials_secret_query_and_fragment_are_removed(self):
        source = (
            "https://synthetic-user:synthetic-password@example.test:8443/path"
            "?access_token=synthetic-token&view=public#synthetic-fragment"
        )
        result, stats = redact(source)
        parts = urlsplit(result)
        self.assertEqual(parts.scheme, "https")
        self.assertEqual(parts.netloc, "example.test:8443")
        self.assertEqual(parts.path, "/path")
        self.assertEqual(parse_qsl(parts.query), [("access_token", MARKER), ("view", "public")])
        self.assertEqual(parts.fragment, MARKER)
        self.assertEqual(stats, {"url_userinfo": 1, "url_query": 1, "url_fragment": 1})
        self.assertNotIn("synthetic-", result)

    def test_duplicate_and_percent_encoded_query_keys_are_all_redacted(self):
        source = "https://example.test/?api_key=synthetic-first&view=public&%61pi%5Fkey=synthetic-second"
        result, stats = redact(source)
        self.assertEqual(
            parse_qsl(urlsplit(result).query),
            [("api_key", MARKER), ("view", "public"), ("api_key", MARKER)],
        )
        self.assertEqual(stats, {"url_query": 2})

    def test_query_preserves_public_duplicates_and_blank_values(self):
        source = "https://example.test/p?tag=one&tag=two&empty=&api_key=synthetic-token"
        result, _ = redact(source)
        self.assertEqual(
            parse_qsl(urlsplit(result).query, keep_blank_values=True),
            [("tag", "one"), ("tag", "two"), ("empty", ""), ("api_key", MARKER)],
        )

    def test_public_url_preserves_encoded_path_and_query_meaning(self):
        source = "https://example.test/a%2Fb?name=hello%20world&count=5"
        result, stats = redact(source)
        self.assertEqual(urlsplit(result).path, "/a%2Fb")
        self.assertEqual(parse_qsl(urlsplit(result).query), [("name", "hello world"), ("count", "5")])
        self.assertEqual(stats, {})

    def test_url_with_ipv6_host_keeps_valid_host(self):
        result, stats = redact("https://user:synthetic-password@[::1]:8443/path?view=public")
        self.assertEqual(urlsplit(result).netloc, "[::1]:8443")
        self.assertEqual(stats, {"url_userinfo": 1})

    def test_malformed_url_candidates_are_fully_redacted_without_echoing_them(self):
        candidates = (
            "https://[synthetic-secret/path",
            "https://example.test:synthetic-secret/path",
            "https://example.test:99999/path?password=synthetic-secret",
            "https://example.test/path?password=synthetic-secret%ZZ",
            "https://example.test/path?password=synthetic-secret\ntrailing",
            "https://example.test/path?password=synthetic-secret space",
            "https://example.test\\synthetic-secret",
        )
        for source in candidates:
            with self.subTest(kind=candidates.index(source)):
                result, stats = redact(source)
                self.assertEqual(result, MARKER)
                self.assertEqual(stats, {"invalid_url": 1})
                self.assertNotIn("synthetic-secret", json.dumps(stats))

    def test_surrounding_whitespace_does_not_hide_a_url(self):
        result, stats = redact("  https://example.test/?password=synthetic-secret  ")
        self.assertNotIn("synthetic-secret", result)
        self.assertEqual(parse_qsl(urlsplit(result.strip()).query), [("password", MARKER)])
        self.assertEqual(stats, {"url_query": 1})

    def test_ordinary_json_and_free_text_remain_unchanged(self):
        source = [
            {"park_id": "demo", "wait_time": 15, "open": True, "missing": None},
            "A prose message mentioning https://example.test/public is outside URL mode.",
            "Unicode text: 東京 🏰",
            1.25,
            [],
            {},
        ]
        result, stats = redact(source)
        self.assertEqual(result, source)
        self.assertEqual(stats, {})

    def test_metadata_contains_only_fixed_rules_and_counts(self):
        source = {
            "synthetic-private-path": {
                "password": "synthetic-password",
                "tenantSecret": "synthetic-custom-secret",
                "url": "https://example.test/?api_key=synthetic-query#synthetic-fragment",
            }
        }
        result, stats = redact(source, extra_keys=("tenantSecret",))
        self.assert_safe_stats(stats)
        encoded_stats = json.dumps(stats)
        for secret in ("synthetic-", "tenantSecret", "private-path", "example.test"):
            self.assertNotIn(secret, encoded_stats)
        for secret in ("synthetic-password", "synthetic-custom-secret", "synthetic-query", "synthetic-fragment"):
            self.assertNotIn(secret, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
