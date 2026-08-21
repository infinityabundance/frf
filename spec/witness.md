# The witness extension protocol

*Version: `frf-witness-request-v1` / `frf-witness-response-v1`
(`frf-witness-statement-v1` for the recorded attestation).*

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
  the attestation relation is: `{id, relation}` →
  `FRF/WITNESS-SPEC/v1`), the witness IMPLEMENTATION (the program bytes,
  sealed BEFORE it runs, plus its artifact identity), the exact statement,
  the attestation, and the request/response content addresses.

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
  "schema_version": "frf-witness-response-v1",
  "request_id": "<SHA-256 of the exact request bytes received>",
  "indeterminate": false,
  "failure": null,
  "attestation": {
    "statement": "the candidate diverges on the malformed fixture (witnessed)",
    "verified": true,
    "detail": "independent review confirms the statement against the subject content address ..."
  }
}
```

## 4. Fail-closed interpretation

- wrong schema version, unparseable JSON, non-zero exit, timeout → refusal;
- `request_id` MUST equal the request's content address — the response must
  cryptographically name the request it answers;
- `indeterminate` / `failure` → refusal;
- a missing `attestation` is a refusal — an attestation is the ONLY
  admissible outcome (a decline is never recorded as "not verified");
- the attestation's `statement` MUST equal the requested statement — a
  witness cannot attest a different sentence.

## 5. Evidence and verification

The content-addressed `WitnessStatement` is written to
`witnesses/<id>.json` (canonical JSON) with the preserved request and
response under `witnesses/<id>/`. The verified loader rehashes everything
on read: the statement's identity rederives from its own fields, the
preserved documents hash to their cids, the response names its request, and
the attestation names exactly the statement recorded. A hand-edited or
misattributed statement refuses, never silently consumes.
