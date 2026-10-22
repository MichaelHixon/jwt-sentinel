# -*- coding: utf-8 -*-
"""
Unit tests for jwt_sentinel.py.

jwt_sentinel is a Burp extension that imports the Burp Extender API and Java
classes (burp, javax.swing, java.util). Those modules only exist inside Jython
running under Burp, so here we register fake stand-ins in sys.modules BEFORE
importing the module under test. Only assess() and extract_tokens() are
exercised; neither touches the stubbed classes, so the stubs just need to exist.

Run with plain stdlib: python3 -m unittest
"""

import sys
import types
import base64
import json
import time
import unittest


def _install_stubs():
    """Register fake burp / javax / java modules so the import succeeds."""
    def fake(name):
        return type(name, (object,), {})

    burp = types.ModuleType("burp")
    for cls in ("IBurpExtender", "IScannerCheck", "IScanIssue", "IContextMenuFactory"):
        setattr(burp, cls, fake(cls))
    sys.modules["burp"] = burp

    javax = types.ModuleType("javax")
    swing = types.ModuleType("javax.swing")
    swing.JMenuItem = fake("JMenuItem")
    javax.swing = swing
    sys.modules["javax"] = javax
    sys.modules["javax.swing"] = swing

    java = types.ModuleType("java")
    util = types.ModuleType("java.util")
    util.ArrayList = fake("ArrayList")
    java.util = util
    sys.modules["java"] = java
    sys.modules["java.util"] = util


_install_stubs()
import jwt_sentinel as js  # noqa: E402


def make_token(header, payload):
    """Build a syntactic header.payload.sig JWT (base64url, no real signature)."""
    def seg(obj):
        raw = json.dumps(obj).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return seg(header) + "." + seg(payload) + ".AAAA"


def severities(findings):
    return [sev for sev, _ in findings]


def notes(findings):
    return " ".join(note for _, note in findings)


class AssessChecks(unittest.TestCase):

    def test_alg_none(self):
        f = js.assess({"alg": "none"}, {})
        self.assertIn("High", severities(f))
        self.assertIn("alg=none", notes(f))

    def test_alg_none_mixed_case(self):
        # Case-insensitive: "NoNe" must still trip the alg:none check.
        f = js.assess({"alg": "NoNe"}, {})
        self.assertIn("alg=none", notes(f))

    def test_jku_header(self):
        f = js.assess({"alg": "RS256", "jku": "https://evil.example/keys"}, {})
        self.assertIn("'jku'", notes(f))
        self.assertIn("High", severities(f))

    def test_x5u_header(self):
        f = js.assess({"alg": "RS256", "x5u": "https://evil.example/cert"}, {})
        self.assertIn("'x5u'", notes(f))
        self.assertIn("High", severities(f))

    def test_jwk_header(self):
        f = js.assess({"alg": "RS256", "jwk": {"kty": "RSA"}}, {})
        self.assertIn("'jwk'", notes(f))
        self.assertIn("High", severities(f))

    def test_x5c_header(self):
        f = js.assess({"alg": "RS256", "x5c": ["MIIB..."]}, {})
        self.assertIn("'x5c'", notes(f))
        self.assertIn("High", severities(f))

    def test_x5t_header(self):
        # Future exp keeps the no-exp Low check from contaminating the oracle, so
        # the severity we assert is the one bound to the x5t finding itself.
        f = js.assess({"alg": "RS256", "x5t": "abc123"},
                      {"exp": int(time.time()) + 3600})
        self.assertIn("'x5t'", notes(f))
        x5t_sevs = [s for s, n in f if "x5t" in n]
        self.assertEqual(x5t_sevs, ["Low"])  # fails if x5t is mis-rated High

    def test_exp_past(self):
        f = js.assess({"alg": "RS256"}, {"exp": int(time.time()) - 3600})
        self.assertIn("Medium", severities(f))
        self.assertIn("past its exp", notes(f))

    def test_no_exp(self):
        f = js.assess({"alg": "RS256"}, {})
        self.assertIn("No 'exp'", notes(f))
        self.assertIn("Low", severities(f))

    def test_sensitive_claim(self):
        f = js.assess({"alg": "RS256"}, {"exp": int(time.time()) + 3600,
                                         "password": "hunter2"})
        self.assertIn("Sensitive-looking claim", notes(f))
        self.assertIn("password", notes(f))

    def test_sensitive_claim_nested(self):
        # Recursive walk must catch a sensitive key nested inside a sub-object.
        f = js.assess({"alg": "RS256"},
                      {"exp": int(time.time()) + 3600,
                       "profile": {"ssn": "000-00-0000"}})
        self.assertIn("Sensitive-looking claim", notes(f))
        self.assertIn("ssn", notes(f))

    def test_kid_header(self):
        f = js.assess({"alg": "RS256", "kid": "../../etc/passwd"},
                      {"exp": int(time.time()) + 3600})
        self.assertIn("'kid'", notes(f))
        self.assertIn("Low", severities(f))

    def test_hmac_alg(self):
        f = js.assess({"alg": "HS256"}, {"exp": int(time.time()) + 3600})
        self.assertIn("HMAC", notes(f))
        self.assertIn("Information", severities(f))

    def test_asymmetric_alg(self):
        for alg in ("RS256", "ES384"):
            f = js.assess({"alg": alg}, {"exp": int(time.time()) + 3600})
            self.assertIn("Asymmetric", notes(f))
            self.assertIn("Information", severities(f))

    def test_clean_token_no_header_findings(self):
        # A plain HS token with a future exp yields only the HMAC info note.
        f = js.assess({"alg": "HS256"}, {"exp": int(time.time()) + 3600})
        self.assertEqual(severities(f), ["Information"])


class ExtractTokens(unittest.TestCase):

    def test_finds_token(self):
        tok = make_token({"alg": "none"}, {"sub": "1"})
        blob = "Authorization: Bearer " + tok + "\r\n"
        self.assertIn(tok, js.extract_tokens(blob))

    def test_dedup(self):
        tok = make_token({"alg": "none"}, {"sub": "1"})
        self.assertEqual(js.extract_tokens(tok + " " + tok), [tok])

    def test_empty_blob(self):
        self.assertEqual(js.extract_tokens(""), [])
        self.assertEqual(js.extract_tokens(None), [])

    def test_rejects_non_jwt(self):
        # A base64url blob that does not parse as a JWT object is dropped.
        self.assertEqual(js.extract_tokens("eyJhbGciOiJ.notjson.sig"), [])

    def test_rejects_non_object_payload(self):
        # Valid JSON that is not an object (a list) must be dropped: parse_jwt's
        # isinstance guard exists so assess()'s later .get() cannot crash on it.
        hdr = base64.urlsafe_b64encode(b'{"alg":"none"}').decode("ascii").rstrip("=")
        pay = base64.urlsafe_b64encode(b'[1,2,3]').decode("ascii").rstrip("=")
        self.assertEqual(js.extract_tokens(hdr + "." + pay + ".AAAA"), [])


if __name__ == "__main__":
    unittest.main()
