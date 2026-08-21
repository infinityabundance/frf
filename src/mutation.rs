//! Court-challenge mutation operators (spec/challenge.md).
//!
//! A court run that yields a pass proves nothing unless the court has
//! demonstrated it can SEE the defect classes it declares. A mutation
//! operator seeds a defect: it produces a MUTANT candidate — a deterministic
//! wrapper of the admitted reference artifact that alters exactly one
//! observable dimension and preserves every other byte-for-byte — and the
//! challenge runs the court against it. If the court does not observe a
//! divergence on the targeted axis, it is BLIND to the defect class it
//! claims to police.
//!
//! The wrapper is a pure function of (operator, reference artifact hash):
//!
//! ```sh
//! #!/bin/sh
//! ref=objects/sha256/<H>          # the reference snapshot, relative to the
//!                                 # invocation root (resolves in the store)
//! out=$(mktemp) err=$(mktemp)
//! "$ref" "$@" >"$out" 2>"$err"    # run the reference with the court's argv
//! rc=$?
//! <per-operator transform>
//! rm -f "$out" "$err"
//! exit <mutated-or-original rc>
//! ```
//!
//! The untouched streams are re-emitted with `cat` — byte-for-byte — so a
//! healthy court sees a residual on the targeted axis and ONLY on it. The
//! mutant artifact is content-addressed like any candidate; its hash is
//! rederivable from the operator + reference hash, so a verifier regenerates
//! the wrapper and proves the recorded mutant hash.
//!
//! The wrapper locates the reference WITHOUT depending on `$0`: the sealed
//! reference profile executes images from a sealed memfd, so a script's `$0`
//! is its image path (`/proc/self/fd/<n>`), not an `objects/sha256/` path.
//! The wrapper first tries `$0`'s directory (path-based execution), then the
//! FIXTURE argument — the court always passes the fixture as an
//! `objects/sha256/<fixture-hash>` path, and the reference lives in the same
//! directory — so the same deterministic bytes resolve the reference under
//! both execution mechanisms, root-independently and cwd-independently.

use crate::error::{FrfError, Result};

/// The built-in mutation operators, one per built-in observable surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationOperator {
    /// The mutant preserves both streams and exits with a different exit
    /// class: `(rc + 1) mod 256` — always different, deterministically.
    ExitClass,
    /// The mutant preserves stdout + exit and replaces the first stderr line
    /// (prefixing it deterministically; an empty stderr gains one line, so
    /// the surface always differs).
    StderrFirstLine,
    /// The mutant preserves stderr + exit and replaces the first stdout line.
    StdoutFirstLine,
}

impl MutationOperator {
    /// The observable axis this operator seeds a defect on.
    pub fn target_axis(self) -> &'static str {
        match self {
            MutationOperator::ExitClass => "exit",
            MutationOperator::StderrFirstLine => "stderr",
            MutationOperator::StdoutFirstLine => "stdout",
        }
    }

    /// The operator that seeds a defect on `axis`, if the axis has a
    /// built-in mutation surface. Externally served axes have no built-in
    /// operator (a future mutation-extension protocol will serve them).
    pub fn from_axis(axis: &str) -> Option<Self> {
        match axis {
            "exit" => Some(MutationOperator::ExitClass),
            "stderr" => Some(MutationOperator::StderrFirstLine),
            "stdout" => Some(MutationOperator::StdoutFirstLine),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            MutationOperator::ExitClass => "exit-class",
            MutationOperator::StderrFirstLine => "stderr-first-line",
            MutationOperator::StdoutFirstLine => "stdout-first-line",
        }
    }

    pub fn parse(id: &str) -> Result<Self> {
        match id {
            "exit-class" => Ok(MutationOperator::ExitClass),
            "stderr-first-line" => Ok(MutationOperator::StderrFirstLine),
            "stdout-first-line" => Ok(MutationOperator::StdoutFirstLine),
            other => Err(FrfError::new(format!(
                "unknown mutation operator {other:?}: built-ins are exit-class, stderr-first-line, stdout-first-line"
            ))),
        }
    }

    /// The mutant wrapper: a deterministic shell script that re-executes the
    /// reference snapshot and alters exactly the targeted surface. The
    /// wrapper and the reference snapshot live in the SAME `objects/sha256/`
    /// directory (both are content-addressed court artifacts). The reference
    /// is resolved WITHOUT depending on `$0` — under the sealed reference
    /// profile a script's `$0` is its image path, not an `objects/sha256/`
    /// path — so the wrapper tries `$0`'s directory first (path-based
    /// execution) and then the fixture argument (an `objects/sha256/` path
    /// the court always passes, naming the directory the reference lives
    /// in). Root-independent, cwd-independent, and content-addressed: any
    /// verifier regenerates the same bytes from (operator, reference hash),
    /// and the same bytes resolve the reference under both execution
    /// mechanisms. The untouched streams are re-emitted byte-for-byte.
    pub fn wrapper(self, reference_sha256: &str) -> String {
        let preamble = format!(
            "#!/bin/sh\n\
             # FRF court-challenge mutant: {} of objects/sha256/{reference_sha256}\n\
             self_dir=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd) 2>/dev/null || exit 2\n\
             ref=\"$self_dir/{reference_sha256}\"\n\
             if [ ! -f \"$ref\" ]; then\n\
               ref=\"\"\n\
               for arg in \"$@\"; do\n\
                 case \"$arg\" in\n\
                   */objects/sha256/*)\n\
                     dir=$(CDPATH= cd -- \"$(dirname -- \"$arg\")\" && pwd) 2>/dev/null || continue\n\
                     if [ -f \"$dir/{reference_sha256}\" ]; then ref=\"$dir/{reference_sha256}\"; break; fi\
\
                     ;;\n\
                 esac\n\
               done\n\
             fi\n\
             if [ -z \"$ref\" ]; then\n\
               echo \"FRF-MUTANT: cannot locate reference object {reference_sha256}\" >&2\n\
               exit 2\n\
             fi\n\
             out=$(mktemp) || exit 2\n\
             err=$(mktemp) || exit 2\n\
             \"$ref\" \"$@\" >\"$out\" 2>\"$err\"\n\
             rc=$?\n",
            self.as_str()
        );
        match self {
            MutationOperator::ExitClass => format!(
                "{preamble}\
                 cat \"$out\"\n\
                 cat \"$err\" >&2\n\
                 rm -f \"$out\" \"$err\"\n\
                 exit $(( (rc + 1) % 256 ))\n"
            ),
            MutationOperator::StderrFirstLine => format!(
                "{preamble}\
                 cat \"$out\"\n\
                 {{ IFS= read -r first; printf '%s\\n' \"FRF-MUTANT:{op}:${{first}}\"; cat; }} <\"$err\" >&2\n\
                 rm -f \"$out\" \"$err\"\n\
                 exit \"$rc\"\n",
                op = self.as_str()
            ),
            MutationOperator::StdoutFirstLine => format!(
                "{preamble}\
                 {{ IFS= read -r first; printf '%s\\n' \"FRF-MUTANT:{op}:${{first}}\"; cat; }} <\"$out\"\n\
                 cat \"$err\" >&2\n\
                 rm -f \"$out\" \"$err\"\n\
                 exit \"$rc\"\n",
                op = self.as_str()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(op: MutationOperator) -> String {
        op.wrapper(&"a".repeat(64))
    }

    #[test]
    fn operators_round_trip_and_target_their_axis() {
        for op in [
            MutationOperator::ExitClass,
            MutationOperator::StderrFirstLine,
            MutationOperator::StdoutFirstLine,
        ] {
            assert_eq!(MutationOperator::parse(op.as_str()).unwrap(), op);
            assert_eq!(
                MutationOperator::from_axis(op.target_axis()),
                Some(op),
                "{} targets {}",
                op.as_str(),
                op.target_axis()
            );
        }
        assert_eq!(MutationOperator::from_axis("dns.wire"), None);
        assert!(MutationOperator::parse("bogus").is_err());
    }

    #[test]
    fn the_exit_mutant_preserves_both_streams_and_changes_the_exit() {
        let w = wrap(MutationOperator::ExitClass);
        assert!(w.contains("cat \"$out\""));
        assert!(w.contains("cat \"$err\" >&2"));
        assert!(w.contains("exit $(( (rc + 1) % 256 ))"));
    }

    #[test]
    fn the_stderr_mutant_preserves_stdout_and_replaces_the_first_line() {
        let w = wrap(MutationOperator::StderrFirstLine);
        assert!(w.contains("cat \"$out\""));
        assert!(w.contains("IFS= read -r first"));
        assert!(w.contains("FRF-MUTANT:stderr-first-line:"));
        assert!(w.contains("exit \"$rc\""));
    }

    #[test]
    fn the_stdout_mutant_preserves_stderr_and_replaces_the_first_line() {
        let w = wrap(MutationOperator::StdoutFirstLine);
        assert!(w.contains("FRF-MUTANT:stdout-first-line:"));
        assert!(w.contains("cat \"$err\" >&2"));
        assert!(w.contains("exit \"$rc\""));
    }

    #[test]
    fn the_wrapper_is_a_pure_function_of_operator_and_reference() {
        let a = MutationOperator::ExitClass.wrapper(&"a".repeat(64));
        let b = MutationOperator::ExitClass.wrapper(&"a".repeat(64));
        let c = MutationOperator::ExitClass.wrapper(&"b".repeat(64));
        assert_eq!(
            a, b,
            "same (operator, reference) must generate identical bytes"
        );
        assert_ne!(a, c, "a different reference must generate different bytes");
    }
}
