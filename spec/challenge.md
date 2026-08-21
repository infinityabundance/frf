# Court challenge — the negative controls

A court run that yields a pass proves nothing unless the court has
demonstrated it can SEE the defect classes it declares. `frf court
challenge MANIFEST` is that demonstration: for every applicable mutation
operator, it runs the court against a MUTANT candidate and requires the
court to observe a divergence on the targeted axis — and only on it.

The challenge is fail-closed: a court that is blind to a seeded defect
(no divergence on the targeted axis) or conflates it with another axis
(divergences on unaffected axes) is REFUSED — the challenge records remain
as evidence, but the command exits non-zero.

## Mutation operators

Each operator seeds a defect in exactly one observable dimension. The
built-ins mirror the built-in observable surfaces:

| Operator             | Targeted axis | The seeded defect                                    |
| -------------------- | ------------- | ---------------------------------------------------- |
| `exit-class`         | `exit`        | the mutant exits `(rc + 1) mod 256` — always a       |
|                      |               | different exit class, deterministically              |
| `stderr-first-line`  | `stderr`      | the first stderr line is prefixed                    |
|                      |               | `FRF-MUTANT:stderr-first-line:` (an empty stderr     |
|                      |               | gains one line, so the surface always differs)       |
| `stdout-first-line`  | `stdout`      | the first stdout line is prefixed similarly          |

Externally served axes have no built-in operator (a future mutation
extension protocol will serve them); the default operator set is every
built-in operator whose targeted axis the court declares, and `--operators
exit-class,stderr-first-line` overrides the set. An operator whose
targeted axis the court does not declare is refused: the seeded defect
would be unobservable.

## The mutant candidate

The mutant is a deterministic wrapper of the ADMITTED REFERENCE artifact
(a mutation alters the reference, not the candidate label):

```sh
#!/bin/sh
# FRF court-challenge mutant: exit-class of objects/sha256/<reference>
self_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ref="$self_dir/<reference-hash>"     # the wrapper and the reference live in
                                     # the same objects/sha256/ directory
out=$(mktemp) || exit 2
err=$(mktemp) || exit 2
"$ref" "$@" >"$out" 2>"$err"         # run the reference with the court's argv
rc=$?
# per-operator transform: re-emit the untouched streams byte-for-byte,
# replace/precede the targeted surface, then exit with the mutated code
rm -f "$out" "$err"
exit $(( (rc + 1) % 256 ))
```

Because the wrapper resolves the reference RELATIVE TO ITSELF (both are
content-addressed objects in the same directory), the mutant bytes depend
only on (operator, reference hash): root-independent, cwd-independent, and
rederivable — a verifier regenerates the wrapper and proves the recorded
mutant hash. The untouched dimensions are re-emitted with `cat`,
byte-for-byte, so a healthy court sees a residual on the targeted axis and
ONLY on it.

The mutant run is an ORDINARY court run — same question, same envelope,
same fixture, mutant candidate — with its own captures, residuals, and
tokens. It replays like any other run (replay re-executes the mutant
snapshot, whose wrapper re-executes the reference snapshot from the same
store).

## The challenge record

`challenges/<id>.yaml`, content-addressed (`FRF/CHALLENGE/v1`):

```text
CourtChallenge {
    id                        FRF/CHALLENGE/v1 over the declared evidence
    court                     the court id exercised
    operator                  the mutation operator
    target_axis               the axis the mutation targeted
    reference_sha256          the admitted reference artifact
    mutant_candidate_sha256   the deterministic wrapper (rederivable)
    run                       the mutant run (an ordinary content-addressed run)
    observed_residuals        the run's residuals        } derived — recomputed
    unaffected_axes           declared observables minus  } by verification,
                              the targeted axis          } never trusted from
    saw_defect                divergence on the target    } the file
    specificity_clean         no divergence on unaffected }
    created_by                runner identity
}
```

The identity covers the DECLARED evidence only; the verdicts are DERIVED
from the run's residuals and recomputed by verification (`verify_tree` and
the challenge suite re-derive them), so a hand-edited verdict is caught as
a lie, and a hand-edited declared field breaks the content address.

## The property

A court that passes this battery on every declared observable has proven
it can see each defect class it claims to police — a passing run against a
real candidate means the court would have caught that defect class had it
been present. The challenge records are the negative-control evidence;
binding them into claim admission (a claim's `requires[]` carrying the
challenge evidence for the claimed axes) is the natural next step once
claims reference challenge records.
