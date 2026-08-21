# The witness extension protocol

*Version: `frf-witness-request-v1` / `frf-witness-response-v3`
(`frf-witness-statement-v3` for the recorded attestation).*

A witness is a *protocol participant*, not Rust code: any program that
speaks this protocol can attest to a content-addressed evidence subject — a
run, a receipt, or a residual — by naming the exact request it answers and
returning an attestation of EXACTLY the statement it was asked. The
attestation is recorded as a content-addressed `WitnessStatement`
(`witnesses/<id>.json`, canonical JSON — the protocol representation, like
receipts) with the canonical request and response preserved as evidence.

The property that makes an attestation binding:

- the subject's **content address is REDERIVED by the core** — the run's
  identity digest, the receipt's digest, or the residual's fingerprint —
  never read from the caller, so a witness cannot be pointed at a forged
  address;
- the statement's identity covers the subject, the witness SEMANTIC (what
  the attestation relation is: `{id, relation, relation_version}` →
  `FRF/WITNESS-SPEC/v2` — the relation's version is part of its semantic
  identity, in every protocol), the witness IMPLEMENTATION (the program
  bytes, sealed BEFORE it runs, plus its artifact identity), the exact
  statement, the attestation, and the request/response content addresses.

## 1. Attesting a subject

```sh
frf witness attest residual cli-exit-0001 \
  --id manual-review \
  --relation independent-confirmation \
  --program golden/witnesses/attest.py \
  --statement "the candidate diverges on the malformed fixture (witnessed)"
```

Subjects: `run RUN_ID`, `receipt RECEIPT_ID`, `residual RESIDUAL_ID`. The
subject is VERIFIED on read before its address is computed (a run through
the verified capture loader, a receipt through the verified receipt
loader), so the content address is derived from evidence that already
proved its own identity and derivation.

## 2. The request

```json
{
  "schema_version": "frf-witness-request-v1",
  "witness": {
    "id": "manual-review",
    "relation_id": "independent-confirmation",
    "relation_version": "v1",
    "specification_hash": "<64-hex>"
  },
  "subject": {
    "kind": "residual",
    "id": "cli-exit-0001",
    "cid": "<the rederived content address>"
  },
  "statement": "the candidate diverges on the malformed fixture (witnessed)",
  "context": {
    "evidence_root": "<the evidence root the subject lives in>"
  }
}
```

## 3. The response

```json
{
  "schema_version": "frf-witness-response-v3",
  "request_id": "<SHA-256 of the exact request bytes received>",
  "indeterminate": false,
  "failure": null,
  "attestation": {
    "statement": "the candidate diverges on the malformed fixture (witnessed)",
    "outcome": "affirm",
    "detail": "independent review confirms the statement against the subject content address ..."
  }
}
```

The response MUST be its own canonical serialization (RFC 8785): the host
strict-parses the bytes, re-encodes the parsed document canonically, and
refuses anything that is not byte-identical — one semantic response has one
evidence identity, so two byte sequences cannot split it.

The attestation's `outcome` is the WITNESS's assertion — `affirm`, `deny`,
or `indeterminate` — and it is recorded as the witness's claim. FRF's own
`verified` is a different predicate: whether the recorded evidence object's
identity and derivations re-prove on read. A witness that says `affirm` is
a witness that affirms; it is not, by that fact alone, proven independent or
truthful.

## 4. Fail-closed interpretation

- wrong schema version, unparseable JSON, non-zero exit, timeout → refusal;
- `request_id` MUST equal the request's content address — the response must
  cryptographically name the request it answers;
- `indeterminate` / `failure` → refusal;
- a missing `attestation` is a refusal — an attestation is the ONLY
  admissible outcome (a decline is never recorded as "not verified");
- the attestation's `statement` MUST equal the requested statement — a
  witness cannot attest a different sentence;
- the attestation's `outcome` MUST be `affirm`, `deny`, or `indeterminate`
  (a closed set — anything else is refused).

## 5. Evidence and verification

The content-addressed `WitnessStatement` is written to
`witnesses/<id>.json` (canonical JSON) with the preserved request and
response under `witnesses/<id>/`. The verified loader rehashes everything
on read: the statement's identity rederives from its own fields, the
preserved documents hash to their cids, the response names its request, and
the attestation names exactly the statement recorded. A hand-edited or
misattributed statement refuses, never silently consumes.

Since v3 the statement also carries two separate identities:

- **`witness_identity`** — the stable WHO: `FRF/WITNESS-IDENTITY/v1` over
  `{specification_hash, implementation_hash, interpreter}`. Two attestations
  with the same identity were made by the same instrument; a different
  identity is a different instrument — and NOTHING more. Identity
  distinctness is never independence.
- **`authority`** — the declared authority the witness says it acts for
  (`{id, kind, detail?}`; `kind` is `person | organization | automated |
  other`), recorded verbatim from the response. The declaration is the
  witness's, never FRF's interpretation.

## 6. The independence relation

Independence is a DECLARED relation, never derived:

```sh
frf witness independence WITNESS_STATEMENT_ID \
  --relation separate-party \
  --basis "the attestation was made by an unaffiliated reviewer against the exported bundle"
```

The closed relations:

| relation | the declarant claims |
|---|---|
| `different-implementation` | the witness program is a different implementation of the relation than the evidence-producing tooling |
| `separate-party` | the witness acted for a party separate from the evidence producer |
| `unaffiliated-channel` | the witness observed through an unaffiliated channel |
| `adversarial-review` | the witness reviewed the evidence adversarially |

Each record (`independence/<id>.json`, `frf-independence-v1`) is
content-addressed over `{subject, witness_statement, witness_identity,
relation, relation_version, specification_hash, basis, detail,
evidence_refs}` and carries a mandatory **basis** — WHY the relation is
claimed. FRF verifies the evidence STRUCTURE: the bound statement verifies
(identity + preserved documents), the witness identity and subject match
the statement, the relation is closed, and the spec hash rederives. It
never verifies the social truth of independence — a different executable
hash is never by itself evidence of independent observation; the
DECLARATION is the evidence. A claim compiled under a witness-requiring
policy carries the independence records bound to its attestations
(`independence_evidence`, claim v7), so the declared independence claims
are as portable as the attestations they qualify.
