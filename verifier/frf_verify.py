#!/usr/bin/env python3
"""frf_verify — the independent FRF verifier.

A deliberately small SECOND implementation of the FRF protocol. It does NO
execution: it loads an OpenReceipt bundle, verifies every content address,
runs the structural and semantic conformance rules, walks the evidence
graph, rederives court identities, residual fingerprints, kappa tokens,
trajectory signs and disposition-event chains, verifies the receipt, and
derives the admissible Claim IR — all from the bundle alone, with no
original source tree and no frf installation.

If the Rust reference engine and this verifier agree on the same bundle,
FRF is a protocol, not a Rust file format. The conformance corpus
(conformance/) is the shared oracle both implementations must pass.

Modes:
  frf_verify.py bundle <dir>              verify a bundle (exit 0, print IR)
  frf_verify.py corpus <conformance-dir>  run the structural + semantic corpus

Requires PyYAML (pip install pyyaml). Uses only the Python standard library
otherwise; the RFC 8785 canonicalizer below is implemented from the RFC,
not imported from anywhere.
"""

import hashlib
import json
import os
import sys

# ---------------------------------------------------------------------------
# RFC 8785 canonical JSON (JCS) — must match the reference engine byte-for-byte
# ---------------------------------------------------------------------------

def _escape(s):
    out = []
    for c in s:
        o = ord(c)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif c == "\b":
            out.append("\\b")
        elif c == "\t":
            out.append("\\t")
        elif c == "\n":
            out.append("\\n")
        elif c == "\f":
            out.append("\\f")
        elif c == "\r":
            out.append("\\r")
        elif o <= 0x1F:
            out.append("\\u%04x" % o)
        else:
            out.append(c)
    return "".join(out)


def jcs(value):
    """Canonical JSON per RFC 8785. The value domain is strings, arrays,
    booleans, and null only — numbers are refused, exactly like the
    reference engine's canonicalizer."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return '"' + _escape(value) + '"'
    if isinstance(value, (int, float)):
        raise ValueError("JSON number %r is outside the OpenReceipt value domain" % (value,))
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        # UTF-16 code-unit ordering (RFC 8785 section 3.2.3): the utf-16-be
        # encoding is exactly the sequence of UTF-16 code units, and byte
        # comparison of those is code-unit comparison. NOT code-point order.
        keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join('"%s":%s' % (_escape(k), jcs(value[k])) for k in keys) + "}"
    raise ValueError("unsupported value %r" % (value,))


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def preimage(kind, doc):
    """The one identity primitive: SHA-256 of FRF/<kind>/v1 + newline + the
    canonical JSON of the document (the identity discipline)."""
    return sha256_bytes((kind + "\n" + jcs(doc)).encode("utf-8"))


# ---------------------------------------------------------------------------
# Rederivations — the same functions the reference engine uses, recomputed here
# ---------------------------------------------------------------------------

def env_digest(os_name, arch, kernel):
    return sha256_bytes(("os=%s\narch=%s\nkernel=%s" % (os_name, arch, kernel)).encode("utf-8"))


def interpreter_hash(artifact):
    interp = artifact.get("interpreter")
    if interp is None:
        return None
    return interp["downstream_interpreter"]["sha256"]


def court_semantic_identity_from_receipt(rec):
    court = rec["court"]
    env = court["admissibility_envelope"]
    fixture = rec["fixtures"][0]
    doc = {
        "question": court["question"],
        "falsifier": court["falsifier"],
        "authority_artifact_identity": rec["authority"]["identity_hash"],
        "fixture": {
            "id": fixture["id"],
            "sha256": fixture["hash"],
            "arguments": fixture["declared_arguments"],
        },
        "envelope": {
            "fixture_family": env["fixture_family"],
            "platforms": env["platforms"],
            "observables": env["observables"],
            "normalizers": env["normalizers"],
            "replay_scope": env["replay_scope"],
        },
        "comparators": [
            {
                "id": c["id"],
                "relation_id": c["relation_id"],
                "relation_version": c["relation_version"],
                "specification_hash": c["specification_hash"],
            }
            for c in rec["comparator_semantics"]
        ],
    }
    return preimage("FRF/COURT/v1", doc)


def residual_fingerprint(record):
    doc = {
        "kind": record["kind"],
        "axis": record["axis"],
        "surface": record.get("surface"),
        "reference_sha256": sha256_bytes(record["raw_reference"].encode("utf-8")),
        "candidate_sha256": sha256_bytes(record["raw_candidate"].encode("utf-8")),
    }
    return preimage("FRF/RESIDUAL-FINGERPRINT/v1", doc)


def _side(s):
    return {
        "exit": s["exit"],
        "stdout_sha256": s["stdout_sha256"],
        "stderr_sha256": s["stderr_sha256"],
        "stdout_first_line": s["stdout_first_line"],
        "stderr_first_line": s["stderr_first_line"],
    }


def run_identity(cap, residuals):
    doc = {
        "court": cap["court"],
        "authority": cap["authority"],
        "authority_interpreter": interpreter_hash(cap["authority_artifact"]),
        "candidate_sha256": cap["candidate_artifact"]["sha256"],
        "candidate_interpreter": interpreter_hash(cap["candidate_artifact"]),
        "fixture_sha256": cap["fixture_sha256"],
        "arguments": cap["arguments"],
        "environment_digest": cap["environment"]["digest"],
        "runner_hash": cap["provenance"]["runner"]["frf_executable_hash"],
        "court_semantic_identity": cap["court_semantic_identity"],
        "reference": _side(cap["reference"]),
        "candidate": _side(cap["candidate"]),
        "residuals": [
            {"kind": r["kind"], "raw_reference": r["raw_reference"], "raw_candidate": r["raw_candidate"]}
            for r in residuals
        ],
    }
    return preimage("FRF/RUN/v1", doc)


def disposition_event_identity(event):
    disp = event
    if disp.get("disposition") == "fixed":
        nested = {
            "kind": "fixed",
            "reason": disp["reason"],
            "resolution_run_id": disp["resolution_run_id"],
            "closure_predicate": disp["closure_predicate"],
        }
    else:
        nested = {"kind": disp["disposition"], "reason": disp["reason"]}
    doc = {
        "residual_id": event["residual_id"],
        "parent_event_id": event.get("parent_event_id"),
        "disposition": nested,
        "evidence_refs": event.get("evidence_refs", []),
    }
    return preimage("FRF/DISPOSITION-EVENT/v1", doc)


KAPPA = {
    "exit": ("exit-class", "class-change", "cli-exit-minimize"),
    "stderr": ("diagnostic-routing", "first-line-token-change", "cli-diagnostic-minimize"),
    "stdout": ("stdout-routing", "first-line-token-change", "cli-stdout-minimize"),
}

DRIFT = ("persistent", "transient", "recurrent")
SLEW = ("stable", "abrupt", "burst", "recurrent")
DISPOSITIONS = ("open", "fixed", "intentional", "environmental", "oracle_version", "harness", "unknown")
CLOSURE_PREDICATE = "fix-court: same court, authority, fixture, arguments, observables, normalizers, environment; axis equality"


def classify_repeat(observed):
    n = len(observed)
    t = [i for i, o in enumerate(observed) if o]
    if not t:
        raise ValueError("no observations in the repeat series")
    if len(t) == n:
        return ("persistent", "stable")
    if t[-1] - t[0] + 1 == len(t):
        if t[0] == 0 or t[-1] == n - 1:
            return ("transient", "abrupt")
        return ("transient", "burst")
    if t[0] == 0 and t[-1] == n - 1:
        return ("recurrent", "recurrent")
    return ("transient", "recurrent")


def expected_token(residual):
    surface, magnitude, _ = KAPPA[residual["axis"]]
    return "%s/%s/%s/%s" % (residual["kind"], surface, magnitude, residual["disposition"])


def expected_blocks(axis, family):
    if axis == "exit":
        return ["%s exit parity" % family]
    if axis == "stderr":
        return ["byte-identical diagnostics"]
    return ["byte-identical stdout"]


# ---------------------------------------------------------------------------
# Structural + semantic conformance (document-level, like validate_semantics)
# ---------------------------------------------------------------------------

REQUIRED_RECEIPT_KEYS = (
    "schema_version", "run", "court", "provenance", "comparator_semantics",
    "authority", "candidate", "environment", "fixtures", "observables",
    "residuals", "endoduction", "claims", "replay",
)


def structural_violations(doc):
    v = []
    if not isinstance(doc, dict):
        return ["receipt is not an object"]
    if doc.get("schema_version") != "frf-receipt-v8":
        v.append("schema_version is %r, expected frf-receipt-v8" % (doc.get("schema_version"),))
    for k in REQUIRED_RECEIPT_KEYS:
        if k not in doc:
            v.append("missing required field %r" % k)
    if isinstance(doc.get("run"), int):
        v.append("run must be a string")
    residuals = doc.get("residuals")
    if isinstance(residuals, list):
        for r in residuals:
            if not isinstance(r, dict):
                v.append("residual entry is not an object")
                continue
            if r.get("disposition") not in DISPOSITIONS:
                v.append("residual %r has unknown disposition %r" % (r.get("id"), r.get("disposition")))
    return v


def semantic_violations(rec):
    v = []
    if rec.get("schema_version") != "frf-receipt-v8":
        v.append("schema_version is %r, expected frf-receipt-v8" % (rec.get("schema_version"),))
    fixtures = rec.get("fixtures", [])
    if len(fixtures) != 1:
        v.append("exactly one fixture is required (found %d)" % len(fixtures))
    envelope = rec["court"]["admissibility_envelope"]
    if envelope.get("replay_scope") != "single-run":
        v.append("replay_scope %r is not executable in v0" % (envelope.get("replay_scope"),))

    declared = []
    for axis in envelope.get("observables", []):
        if axis not in ("exit", "stderr", "stdout"):
            v.append("undeclared observable axis %r" % axis)
        if axis in declared:
            v.append("duplicate declared observable axis %r" % axis)
        else:
            declared.append(axis)

    obs_axes = []
    for obs in rec.get("observables", []):
        if obs["axis"] not in declared:
            v.append("observable %s is not declared in the envelope" % obs["axis"])
        if obs["axis"] in obs_axes:
            v.append("duplicate observable block for axis %s" % obs["axis"])
        else:
            obs_axes.append(obs["axis"])

    sem_ids = []
    for c in rec.get("comparator_semantics", []):
        if c["id"] in sem_ids:
            v.append("duplicate comparator semantic id %s" % c["id"])
        else:
            sem_ids.append(c["id"])
        if c["id"] not in obs_axes:
            v.append("comparator semantic %s serves no observable" % c["id"])
    for obs in rec.get("observables", []):
        n = sum(1 for c in rec.get("comparator_semantics", []) if c["id"] == obs["axis"])
        if n != 1:
            v.append("observable %s must have exactly one comparator semantic (found %d)" % (obs["axis"], n))

    impls = rec.get("provenance", {}).get("comparator_implementations", [])
    if len(impls) != len(rec.get("comparator_semantics", [])):
        v.append("comparator_implementations must mirror comparator_semantics one-to-one")
    for c in rec.get("comparator_semantics", []):
        if not any(i.get("id") == c["id"] for i in impls):
            v.append("comparator semantic %s has no implementation provenance" % c["id"])

    family = envelope.get("fixture_family")
    residual_ids = []
    for r in rec.get("residuals", []):
        rid = r.get("id")
        if rid in residual_ids:
            v.append("duplicate residual id %s" % rid)
        else:
            residual_ids.append(rid)
        if r["axis"] not in declared:
            v.append("residual %s axis %s is not a declared observable" % (rid, r["axis"]))
        kind_ok = (r["kind"] == "exit" and r["axis"] == "exit") or (r["kind"] == "text" and r["axis"] in ("stderr", "stdout"))
        if not kind_ok:
            v.append("residual %s kind %r is inconsistent with axis %s" % (rid, r["kind"], r["axis"]))
        d = r["disposition"]
        if d == "open":
            if r.get("reason") is not None:
                v.append("open residual %s carries a reason" % rid)
            if r.get("resolution_run_id") is not None:
                v.append("open residual %s carries a resolution_run_id" % rid)
            if r.get("closure_predicate") is not None:
                v.append("open residual %s carries a closure_predicate" % rid)
            if r.get("disposition_event_id") is not None:
                v.append("open residual %s carries a disposition_event_id" % rid)
        elif d == "fixed":
            if r.get("reason") is None:
                v.append("fixed residual %s without a reason" % rid)
            if r.get("resolution_run_id") is None:
                v.append("fixed residual %s without a resolution_run_id" % rid)
            if r.get("closure_predicate") != CLOSURE_PREDICATE:
                v.append("fixed residual %s must carry the fix-court closure predicate" % rid)
            if r.get("disposition_event_id") is None:
                v.append("fixed residual %s without a disposition_event_id" % rid)
        else:
            if d not in DISPOSITIONS:
                v.append("residual %s has unknown disposition %r" % (rid, d))
            if r.get("reason") is None:
                v.append("%s residual %s requires a reason" % (d, rid))
            if r.get("resolution_run_id") is not None:
                v.append("%s residual %s carries a resolution_run_id" % (d, rid))
            if r.get("closure_predicate") is not None:
                v.append("%s residual %s carries a closure_predicate" % (d, rid))
            if r.get("disposition_event_id") is None:
                v.append("%s residual %s without a disposition_event_id" % (d, rid))
        grammar = {
            "open": "violation", "fixed": "recovery", "intentional": "intentional_divergence",
            "environmental": "boundary", "oracle_version": "boundary",
            "harness": "boundary", "unknown": "unknown",
        }.get(d)
        if r.get("grammar_state") != grammar:
            v.append("grammar_state of %s is %r, expected %r" % (rid, r.get("grammar_state"), grammar))
        sign = r.get("sign", {})
        if sign.get("norm") == "single-run":
            if sign.get("drift") != "not-observed" or sign.get("slew") != "not-observed":
                v.append("single-run residual %s must carry drift/slew not-observed" % rid)
        elif sign.get("norm") == "repeated-run":
            if sign.get("drift") not in DRIFT:
                v.append("repeated-run residual %s has invalid drift %r" % (rid, sign.get("drift")))
            if sign.get("slew") not in SLEW:
                v.append("repeated-run residual %s has invalid slew %r" % (rid, sign.get("slew")))
        else:
            v.append("residual %s has invalid sign norm %r" % (rid, sign.get("norm")))
        if r.get("reproducer") != rec.get("run"):
            v.append("residual %s reproducer must be the receipt's run" % rid)

    for obs in rec.get("observables", []):
        has = any(r["axis"] == obs["axis"] for r in rec.get("residuals", []))
        if obs["verdict"] == "pass" and has:
            v.append("pass verdict on %s while a residual exists" % obs["axis"])
        if obs["verdict"] == "residual" and not has:
            v.append("residual verdict on %s without any residual" % obs["axis"])

    env = rec.get("environment", {})
    if env_digest(env.get("os"), env.get("architecture"), env.get("kernel_release")) != env.get("digest"):
        v.append("the environment digest does not rederive")

    try:
        if court_semantic_identity_from_receipt(rec) != rec["court"].get("semantic_identity"):
            v.append("the court semantic identity does not rederive from the document")
    except Exception as e:
        v.append("the court semantic identity cannot be rederived: %s" % e)

    replay = rec.get("replay", {})
    if replay.get("program") != "frf":
        v.append('replay.program must be "frf"')
    if replay.get("expected_run_identity") != rec.get("run"):
        v.append("replay.expected_run_identity must equal the receipt's run")
    argv = replay.get("argv", [])
    if len(argv) < 5 or argv[0] != "--root" or argv[2] != "court" or argv[3] != "run":
        v.append("replay.argv must be a court-run invocation")

    tokens = rec.get("endoduction", {}).get("tokens", [])
    if len(tokens) != len(rec.get("residuals", [])):
        v.append("endoduction tokens must mirror residuals one-to-one")
    for r, t in zip(rec.get("residuals", []), tokens):
        if t.get("residual_id") != r["id"]:
            v.append("token bound to %s but the residual is %s" % (t.get("residual_id"), r["id"]))
            continue
        if t.get("token") != expected_token(r):
            v.append("token of %s does not rederive" % r["id"])
        if t.get("next_court") != KAPPA[r["axis"]][2]:
            v.append("next_court of %s does not rederive" % r["id"])
        if t.get("blocks_claims") != expected_blocks(r["axis"], family):
            v.append("blocks_claims of %s does not rederive" % r["id"])

    for who, interp in (("authority", rec.get("authority", {}).get("interpreter")),
                        ("candidate", rec.get("candidate", {}).get("interpreter"))):
        if interp is not None:
            if interp.get("resolver") is not None:
                if interp["resolver"].get("kind") != "env":
                    v.append('%s interpreter resolver kind must be "env"' % who)
                if interp["resolver"].get("path") != interp["kernel_interpreter"].get("path"):
                    v.append("%s interpreter resolver path must be the kernel interpreter path" % who)
            else:
                if interp.get("kernel_interpreter") != interp.get("downstream_interpreter"):
                    v.append("%s interpreter: without a resolver the kernel must BE the downstream interpreter" % who)

    if len(fixtures) == 1:
        f = fixtures[0]
        for i, (resolved, declared_arg) in enumerate(zip(f.get("arguments", []), f.get("declared_arguments", []))):
            if resolved != declared_arg and declared_arg != "{fixture}":
                v.append("argv[%d] %r is neither the declared argument nor a {fixture} substitution" % (i, resolved))

    if rec.get("claims", {}).get("positive"):
        v.append("v0 receipts carry no positive claims; the claim compiler writes claims/")

    return v


# ---------------------------------------------------------------------------
# The admissible Claim IR — mirrors the claim compiler's dependency algebra
# ---------------------------------------------------------------------------

def claim_ir(rec):
    residuals = rec.get("residuals", [])
    harness = [r for r in residuals if r["disposition"] == "harness"]
    blocking = [r for r in residuals if r["disposition"] in ("open", "unknown")]
    scope = [o["axis"] for o in rec.get("observables", []) if not any(r["axis"] == o["axis"] for r in residuals)]
    return {
        "admissible": not harness and len(scope) > 0,
        "harness_invalidated": bool(harness),
        "observable_scope": scope,
        "excluded_residuals": [r["id"] for r in residuals],
        "blockers": [r["id"] for r in blocking],
    }


# ---------------------------------------------------------------------------
# Bundle verification — no execution, no original tree
# ---------------------------------------------------------------------------

def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_yaml(path):
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _safe_rel(bundle, rel):
    if rel.startswith("/") or ".." in rel.split("/"):
        raise ValueError("inventory path %r escapes the bundle" % rel)
    return os.path.join(bundle, rel)


def _axis_agrees(side_ref, side_cand, axis):
    if axis == "exit":
        return side_ref["exit"] == side_cand["exit"]
    if axis == "stderr":
        return side_ref["stderr_first_line"] == side_cand["stderr_first_line"]
    return side_ref["stdout_first_line"] == side_cand["stdout_first_line"]


def _needed_closure(bundle, receipt_id):
    """Mirror of the reference engine's closure walk: the receipt, its run,
    every resolution run its disposition events reference (transitively),
    and for each run the capture + side files, snapshots, residuals + events,
    and trajectories."""
    needed = set()
    runs = []
    seen_runs = set()
    seen_residuals = set()

    needed.add("receipts/%s.json" % receipt_id)
    rec = _load_json(_safe_rel(bundle, "receipts/%s.json" % receipt_id))
    runs.append(rec["run"])

    while runs:
        run = runs.pop()
        if run in seen_runs:
            continue
        seen_runs.add(run)
        cap = _load_yaml(_safe_rel(bundle, "captures/%s/capture.yaml" % run))
        needed.add("captures/%s/capture.yaml" % run)
        for side in ("reference", "candidate"):
            for f in ("stdout", "stderr", "exit.txt", "stderr_first_line.txt", "stdout_first_line.txt"):
                needed.add("captures/%s/%s.%s" % (run, side, f))
        for h in (cap["authority_artifact"]["sha256"], cap["candidate_artifact"]["sha256"], cap["fixture_sha256"]):
            needed.add("objects/sha256/%s" % h)
        for rid in cap.get("residuals", []):
            if rid in seen_residuals:
                continue
            seen_residuals.add(rid)
            needed.add("residuals/%s.yaml" % rid)
            ev_dir = "residuals/%s.events" % rid
            ev_path = _safe_rel(bundle, ev_dir)
            if os.path.isdir(ev_path):
                for name in sorted(n for n in os.listdir(ev_path) if n.endswith(".yaml")):
                    needed.add("%s/%s" % (ev_dir, name))
            if cap.get("repeat_index") is not None:
                record = _load_yaml(_safe_rel(bundle, "residuals/%s.yaml" % rid))
                needed.add("trajectories/%s.yaml" % residual_fingerprint(record))
    return needed


def verify_bundle(bundle):
    manifest = _load_json(_safe_rel(bundle, "manifest.json"))
    if manifest.get("schema_version") != "frf-bundle-v1":
        raise ValueError("unsupported bundle schema version %r" % (manifest.get("schema_version"),))
    receipt_id = manifest.get("receipt_id")
    if not receipt_id:
        raise ValueError("manifest.json carries no receipt_id")

    # 1. Prove the manifest: every inventory file exists and hashes to its
    # recorded digest; objects are named by their digest.
    inventory = {}
    for item in manifest.get("inventory", []):
        rel, sha, kind = item["path"], item["sha256"], item["kind"]
        actual = sha256_bytes(_read(_safe_rel(bundle, rel)))
        if actual != sha:
            raise ValueError("bundle is corrupt: %s hashes to %s but the manifest records %s" % (rel, actual[:16], sha))
        if kind == "object" and os.path.basename(rel) != sha:
            raise ValueError("bundle is corrupt: object file %s is not named by its digest" % rel)
        inventory[rel] = sha

    # 2. The receipt: content-addressed, structurally and semantically valid.
    rest = receipt_id[len("receipt-"):] if receipt_id.startswith("receipt-") else None
    if rest is None or "-" not in rest:
        raise ValueError("receipt id %r is malformed" % receipt_id)
    run = rest.rsplit("-", 1)[0]
    digest = rest.rsplit("-", 1)[1]
    body = _load_json(_safe_rel(bundle, "receipts/%s.json" % receipt_id))
    if body.get("run") != run:
        raise ValueError("receipt %s: the run field does not match its id" % receipt_id)
    if sha256_bytes(jcs(body).encode("utf-8")) != digest:
        raise ValueError("receipt %s is not content-addressed" % receipt_id)
    struct = structural_violations(body)
    if struct:
        raise ValueError("receipt %s fails structural conformance: %s" % (receipt_id, "; ".join(struct)))
    semantic = semantic_violations(body)
    if semantic:
        raise ValueError("receipt %s fails semantic conformance: %s" % (receipt_id, "; ".join(semantic)))

    # 3. The capture: run identity rederives; raw side files rehash; objects
    # are content-addressed.
    cap = _load_yaml(_safe_rel(bundle, "captures/%s/capture.yaml" % run))
    if cap.get("run") != run:
        raise ValueError("capture %s: the run field inside capture.yaml does not match" % run)
    residuals = {}
    for rid in cap.get("residuals", []):
        residuals[rid] = _load_yaml(_safe_rel(bundle, "residuals/%s.yaml" % rid))
    expected_run = "run-%s-%s" % (cap["court"], run_identity(cap, [residuals[r] for r in cap.get("residuals", [])]))
    if expected_run != run:
        raise ValueError("capture %s: the recorded fields do not hash to the run identity" % run)
    for side, s in (("reference", cap["reference"]), ("candidate", cap["candidate"])):
        stdout = _read(_safe_rel(bundle, "captures/%s/%s.stdout" % (run, side)))
        stderr = _read(_safe_rel(bundle, "captures/%s/%s.stderr" % (run, side)))
        if sha256_bytes(stdout) != s["stdout_sha256"]:
            raise ValueError("capture %s: %s.stdout does not hash to the recorded value" % (run, side))
        if sha256_bytes(stderr) != s["stderr_sha256"]:
            raise ValueError("capture %s: %s.stderr does not hash to the recorded value" % (run, side))
        first_out = stdout.decode("utf-8", "replace").split("\n", 1)[0]
        first_err = stderr.decode("utf-8", "replace").split("\n", 1)[0]
        if first_out != s["stdout_first_line"] or first_err != s["stderr_first_line"]:
            raise ValueError("capture %s: %s first lines do not derive" % (run, side))
        for f, recorded, recorded_hash in (
            ("exit.txt", s["exit"], s["exit_sha256"]),
            ("stderr_first_line.txt", s["stderr_first_line"], s["stderr_first_line_sha256"]),
            ("stdout_first_line.txt", s["stdout_first_line"], s["stdout_first_line_sha256"]),
        ):
            text = _read(_safe_rel(bundle, "captures/%s/%s.%s" % (run, side, f)))
            if text.decode("utf-8", "replace").strip() != recorded:
                raise ValueError("capture %s: %s.%s does not derive to the recorded projection" % (run, side, f))
            if sha256_bytes(recorded.encode("utf-8")) != recorded_hash:
                raise ValueError("capture %s: %s.%s hash does not rederive" % (run, side, f))
    for h in (cap["authority_artifact"]["sha256"], cap["candidate_artifact"]["sha256"], cap["fixture_sha256"]):
        if sha256_bytes(_read(_safe_rel(bundle, "objects/sha256/%s" % h))) != h:
            raise ValueError("object %s is corrupt (or missing)" % h)

    # 4. Residuals: records rederive their fingerprints and raw hashes; the
    # receipt entries derive from the records; dispositions are bound to the
    # exact event and the chain is hash-verified; signs derive from the
    # trajectories; tokens rederive.
    for r in body.get("residuals", []):
        rid = r["id"]
        if rid not in residuals:
            raise ValueError("receipt residual %s is not in the run's capture" % rid)
        record = residuals[rid]
        if record.get("run") != run:
            raise ValueError("residual %s belongs to another run" % rid)
        if r["axis"] != record["axis"] or r["kind"] != record["kind"]:
            raise ValueError("residual %s does not derive from its record file" % rid)
        if r["raw_reference_hash"] != record["raw_reference_sha256"] or r["raw_candidate_hash"] != record["raw_candidate_sha256"]:
            raise ValueError("residual %s raw hashes do not rederive" % rid)
        if r["residual_fingerprint"] != residual_fingerprint(record):
            raise ValueError("residual fingerprint of %s does not rederive" % rid)

        ev_dir = _safe_rel(bundle, "residuals/%s.events" % rid)
        events = []
        if os.path.isdir(ev_dir):
            names = sorted(n for n in os.listdir(ev_dir) if n.endswith(".yaml"))
            events = [_load_yaml(os.path.join(ev_dir, n)) for n in names]
        prev = None
        for e in events:
            if disposition_event_identity(e) != e["event_id"]:
                raise ValueError("disposition event %s of %s is not content-addressed" % (e["event_id"][:16], rid))
            if e.get("parent_event_id") != prev:
                raise ValueError("disposition event chain of %s is broken" % rid)
            prev = e["event_id"]
        if r["disposition"] == "open":
            if r.get("disposition_event_id") is not None:
                raise ValueError("open residual %s claims a disposition_event_id" % rid)
        else:
            eid = r.get("disposition_event_id")
            event = next((e for e in events if e.get("event_id") == eid), None)
            if event is None:
                raise ValueError("residual %s binds event %s which is not in its chain" % (rid, eid))
            if event.get("disposition") != r["disposition"] or event.get("reason") != r.get("reason"):
                raise ValueError("residual %s disposition/reason does not match the bound event" % rid)
            if event.get("resolution_run_id") != r.get("resolution_run_id"):
                raise ValueError("residual %s resolution edge does not match the bound event" % rid)
            if (event.get("closure_predicate") if event.get("disposition") == "fixed" else None) != r.get("closure_predicate"):
                raise ValueError("residual %s closure predicate does not match the bound event" % rid)

        if r["sign"]["norm"] == "single-run":
            if r["sign"]["drift"] != "not-observed" or r["sign"]["slew"] != "not-observed":
                raise ValueError("single-run residual %s must carry not-observed drift/slew" % rid)
        else:
            t = _load_yaml(_safe_rel(bundle, "trajectories/%s.yaml" % residual_fingerprint(record)))
            if t["derivation"]["drift"] != r["sign"]["drift"] or t["derivation"]["slew"] != r["sign"]["slew"]:
                raise ValueError("residual %s sign does not match its trajectory" % rid)

        token = next((t for t in body["endoduction"]["tokens"] if t["residual_id"] == rid), None)
        if token is None:
            raise ValueError("no token bound for %s" % rid)
        family = cap["court_spec"]["admissibility_envelope"]["fixture_family"]
        if token["token"] != expected_token(r) or token["next_court"] != KAPPA[r["axis"]][2] \
                or token["blocks_claims"] != expected_blocks(r["axis"], family):
            raise ValueError("the endoduction token of %s does not rederive" % rid)

    # 5. Resolution edges: a fixed closure must be backed by a run that
    # reran the same question under a compatible envelope and closed the axis.
    for r in body.get("residuals", []):
        resolution_run_id = r.get("resolution_run_id")
        if resolution_run_id is None:
            continue
        if resolution_run_id == run:
            raise ValueError("residual %s claims to be fixed by the run that observed it" % r["id"])
        res_cap = _load_yaml(_safe_rel(bundle, "captures/%s/capture.yaml" % resolution_run_id))
        if res_cap.get("court_semantic_identity") != cap["court_semantic_identity"]:
            raise ValueError("resolution run %s does not rerun the same question" % resolution_run_id)
        if res_cap["environment"]["digest"] != cap["environment"]["digest"]:
            raise ValueError("resolution run %s crossed an environment boundary" % resolution_run_id)
        if not _axis_agrees(res_cap["reference"], res_cap["candidate"], r["axis"]):
            raise ValueError("resolution run %s does not close the %s axis" % (resolution_run_id, r["axis"]))

    # 6. The manifest covers the receipt's complete required closure.
    for rel in _needed_closure(bundle, receipt_id):
        if rel not in inventory:
            raise ValueError("bundle closure incomplete: %s is missing" % rel)

    ir = claim_ir(body)
    print("verified: bundle=%s receipt=%s run=%s files=%d" % (bundle, receipt_id, run, len(inventory)))
    print("claim-ir: admissible=%s harness=%s observable_scope=%s excluded_residuals=%s blockers=%s"
          % (str(ir["admissible"]).lower(), str(ir["harness_invalidated"]).lower(),
             json.dumps(ir["observable_scope"]), json.dumps(ir["excluded_residuals"]),
             json.dumps(ir["blockers"])))
    return ir


# ---------------------------------------------------------------------------
# Corpus mode — the shared oracle both implementations must pass
# ---------------------------------------------------------------------------

def verify_corpus(dir_):
    count = 0
    for name in sorted(os.listdir(os.path.join(dir_, "valid"))):
        doc = _load_json(os.path.join(dir_, "valid", name))
        canonical = jcs(doc)
        expected = _read(os.path.join(dir_, "canonical", name)).decode("utf-8")
        if canonical != expected:
            raise ValueError("valid/%s: canonical bytes drifted" % name)
        digest = sha256_bytes(canonical.encode("utf-8"))
        pinned = _read(os.path.join(dir_, "hashes", name + ".sha256")).decode("utf-8").strip()
        if digest != pinned:
            raise ValueError("valid/%s: digest drifted" % name)
        count += 1
    for name in sorted(os.listdir(os.path.join(dir_, "invalid"))):
        path = os.path.join(dir_, "invalid", name)
        with open(path, "r", encoding="utf-8") as f:
            try:
                doc = json.load(f)
            except ValueError:
                continue  # malformed JSON is a refusal
        if not structural_violations(doc):
            raise ValueError("invalid/%s: must be refused" % name)
        count += 1
    for name in sorted(os.listdir(os.path.join(dir_, "invalid-semantic"))):
        path = os.path.join(dir_, "invalid-semantic", name)
        doc = _load_json(path)
        if structural_violations(doc):
            raise ValueError("invalid-semantic/%s: must be structurally valid" % name)
        if not semantic_violations(doc):
            raise ValueError("invalid-semantic/%s: must fail semantic conformance" % name)
        count += 1
    print("corpus %s: %d fixture(s) passed" % (dir_, count))


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    mode, target = argv[1], argv[2]
    try:
        if mode == "bundle":
            verify_bundle(target)
        elif mode == "corpus":
            verify_corpus(target)
        else:
            print("unknown mode %r" % mode, file=sys.stderr)
            return 2
    except (ValueError, KeyError, OSError) as e:
        print("frf_verify: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
