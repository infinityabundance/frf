//! Deterministic endoduction: κ maps a raw residual to a typed token.
//!
//! This is the entire inference machinery of v0 — a lookup/classification
//! table, not a model. The table is auditable in one pass:
//!
//! | axis    | token surface      | magnitude               | next_court              | blocks                              |
//! |---------|--------------------|-------------------------|-------------------------|-------------------------------------|
//! | exit    | exit-class         | class-change            | cli-exit-minimize       | `{scope} exit parity`               |
//! | stderr  | diagnostic-routing  | first-line-token-change | cli-diagnostic-minimize | byte-identical diagnostics          |
//! | stdout  | stdout-routing      | first-line-token-change | cli-stdout-minimize     | byte-identical stdout               |
//! | tls.heartbeat.illegal_response | verdict-scan | observed    | leak-minimize           | `{scope} tls.heartbeat.illegal_response parity` |
//! | memory.leak.seeded_canary | canary-scan  | observed                | leak-minimize           | `{scope} memory.leak.seeded_canary parity` |
//! | (other) | `{axis}-divergence` | observed                | none                    | `{scope} {axis} parity`             |
//!
//! The generic row is deterministic and honest: an axis the built-in router
//! does not know gets no fabricated minimizer target (`next_court: none`),
//! while its open residuals still block exactly the `{scope} {axis} parity`
//! claim phrases. Values follow Section 6 (token grammar example) and Section
//! 12 (routing targets and blocked-claim phrases) of the paper. κ is pure:
//! the same residual record always yields the same token, so receipts and
//! on-disk token files cannot drift.

use crate::model::*;

/// One row of the κ classification table, keyed on the AXIS (the comparator
/// identity, not the text/exit kind): the token surface, magnitude, and
/// routing target. Exposed so the OpenReceipt semantic validator can rederive
/// a receipt's tokens from its own fields — no implementation coupling.
pub struct TokenShape {
    pub surface: String,
    pub magnitude: String,
    pub next_court: String,
}

/// The κ table: axis → (surface, magnitude, next_court). Built-in rows as in
/// the table above; any other axis gets the deterministic generic row (the
/// axis id names the surface, and no routed minimizer exists for an axis the
/// router does not know).
pub fn token_shape(axis: &ObservableId) -> TokenShape {
    match axis.as_str() {
        "exit" => TokenShape {
            surface: "exit-class".to_string(),
            magnitude: "class-change".to_string(),
            next_court: "cli-exit-minimize".to_string(),
        },
        "stderr" => TokenShape {
            surface: "diagnostic-routing".to_string(),
            magnitude: "first-line-token-change".to_string(),
            next_court: "cli-diagnostic-minimize".to_string(),
        },
        "stdout" => TokenShape {
            surface: "stdout-routing".to_string(),
            magnitude: "first-line-token-change".to_string(),
            next_court: "cli-stdout-minimize".to_string(),
        },
        // The Heartbleed information-leak axes (external-corpus/v3/heartbleed):
        // routed rows like the built-ins, so the declared minimizer
        // (`leak-minimize`) can serve either axis's residuals via
        // `frf court minimize`. The split is deliberate: the illegal-response
        // proposition (a malformed heartbeat was answered) and the
        // seeded-canary proposition (the exact synthetic canary bytes escaped)
        // are separate observables with separate comparators.
        "tls.heartbeat.illegal_response" => TokenShape {
            surface: "verdict-scan".to_string(),
            magnitude: "observed".to_string(),
            next_court: "leak-minimize".to_string(),
        },
        "memory.leak.seeded_canary" => TokenShape {
            surface: "canary-scan".to_string(),
            magnitude: "observed".to_string(),
            next_court: "leak-minimize".to_string(),
        },
        // The Goto Fail verdict axis (external-corpus/v3/goto-fail): the
        // SECOND semantic domain — a TLS-verdict observable, not an
        // information leak. Routed like the built-ins, so the declared
        // minimizer (`ssl-handshake-minimize`) can serve its residuals.
        "tls.verdict" => TokenShape {
            surface: "verdict-scan".to_string(),
            magnitude: "observed".to_string(),
            next_court: "ssl-handshake-minimize".to_string(),
        },
        other => TokenShape {
            surface: format!("{other}-divergence"),
            magnitude: "observed".to_string(),
            next_court: "none".to_string(),
        },
    }
}

/// The claim phrases this axis's residual blocks (the token's `blocks_claims`
/// field). The exit block names the fixture family: that is the scope the
/// divergence threatens. For an axis the built-in router does not know, the
/// blocked phrase names the axis itself — an open residual on it blocks
/// exactly the claims about that axis. Also exposed for the semantic
/// validator.
pub fn blocks_claims(axis: &ObservableId, scope: &str) -> Vec<String> {
    match axis.as_str() {
        "exit" => vec![format!("{scope} exit parity")],
        "stderr" => vec!["byte-identical diagnostics".to_string()],
        "stdout" => vec!["byte-identical stdout".to_string()],
        other => vec![format!("{scope} {other} parity")],
    }
}

/// κ(r_raw, disposition) → (kind, surface, authority, magnitude, scope,
/// disposition, next_court). Pure: the same residual record and disposition
/// always yield the same token, so receipts and on-disk token files cannot
/// drift. The disposition is passed in because the observation record itself
/// is immutable; the current disposition is the projection of the residual's
/// event history.
pub fn kappa(r: &ResidualRecord, disposition: &Disposition) -> TokenRecord {
    let shape = token_shape(&r.axis);
    let disposition = disposition.as_str().to_string();
    TokenRecord {
        schema_version: TOKEN_SCHEMA_VERSION.to_string(),
        residual_id: r.id.clone(),
        token: format!(
            "{}/{}/{}/{}",
            r.kind.as_str(),
            shape.surface,
            shape.magnitude,
            disposition
        ),
        kind: r.kind.clone(),
        surface: shape.surface,
        authority: r.authority.clone(),
        magnitude: shape.magnitude,
        scope: r.scope.clone(),
        disposition,
        next_court: shape.next_court,
        blocks_claims: blocks_claims(&r.axis, &r.scope),
    }
}

/// Appendix A `grammar_state` derived from disposition. Mapping table:
///
/// | disposition    | grammar_state       |
/// |----------------|---------------------|
/// | open           | violation           |
/// | fixed          | recovery            |
/// | nonreproduced  | recovery            |
/// | stabilized     | recovery            |
/// | intentional    | intentional_divergence |
/// | environmental  | boundary            |
/// | oracle_version | boundary            |
/// | harness        | boundary            |
/// | unknown        | unknown             |
pub fn grammar_state(disposition: &Disposition) -> &'static str {
    match disposition {
        Disposition::Open => "violation",
        Disposition::Fixed { .. }
        | Disposition::Nonreproduced { .. }
        | Disposition::Stabilized { .. } => "recovery",
        Disposition::Closed { kind, .. } => match kind {
            ClosureKind::Intentional => "intentional_divergence",
            ClosureKind::Environmental => "boundary",
            ClosureKind::OracleVersion => "boundary",
            ClosureKind::Harness => "boundary",
            ClosureKind::Unknown => "unknown",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn residual(kind: ResidualKind, scope: &str) -> ResidualRecord {
        let kind_str = kind.as_str().to_string();
        ResidualRecord {
            schema_version: SCHEMA_RESIDUAL.to_string(),
            id: format!("cli-{}-0001", kind.as_str()),
            court: "cli-malformed-input".to_string(),
            run: "run-cli-malformed-input-ab12cd34".to_string(),
            axis: match kind.as_str() {
                "exit" => ObservableId::exit(),
                _ => ObservableId::stderr(),
            },
            kind: kind.clone(),
            surface: match kind_str.as_str() {
                "exit" => None,
                _ => Some("first-diagnostic-line".to_string()),
            },
            authority: "ref-cli-1.8.2".to_string(),
            scope: scope.to_string(),
            candidate_sha256: "c".repeat(64),
            raw_reference: "2".to_string(),
            raw_candidate: "1".to_string(),
            raw_reference_sha256: "a".repeat(64),
            raw_candidate_sha256: "b".repeat(64),
        }
    }

    fn fixed() -> Disposition {
        Disposition::Fixed {
            reason: "candidate patched".into(),
            resolution_run_id: "run-x".into(),
            closure_predicate: CLOSURE_PREDICATE_FIX_COURT.into(),
        }
    }

    #[test]
    fn kappa_is_deterministic() {
        let r = residual(ResidualKind::exit(), "malformed-input");
        assert_eq!(kappa(&r, &Disposition::Open), kappa(&r, &Disposition::Open));
    }

    #[test]
    fn kappa_exit_maps_to_exit_minimize() {
        let r = residual(ResidualKind::exit(), "malformed-input");
        let t = kappa(&r, &Disposition::Open);
        assert_eq!(t.token, "exit/exit-class/class-change/open");
        assert_eq!(t.next_court, "cli-exit-minimize");
        assert_eq!(t.blocks_claims, vec!["malformed-input exit parity"]);
        assert_eq!(t.authority, "ref-cli-1.8.2");
        assert_eq!(t.scope, "malformed-input");
    }

    #[test]
    fn kappa_text_maps_to_diagnostic_minimize() {
        let r = residual(ResidualKind::text(), "malformed-input");
        let t = kappa(&r, &Disposition::Open);
        assert_eq!(
            t.token,
            "text/diagnostic-routing/first-line-token-change/open"
        );
        assert_eq!(t.next_court, "cli-diagnostic-minimize");
        assert_eq!(t.blocks_claims, vec!["byte-identical diagnostics"]);
    }

    #[test]
    fn kappa_stdout_maps_to_stdout_minimize() {
        // A stdout residual is text-family but routes to its own minimizer:
        // the token table is keyed on the axis, not the text/exit kind.
        let mut r = residual(ResidualKind::text(), "malformed-input");
        r.axis = ObservableId::stdout();
        let t = kappa(&r, &Disposition::Open);
        assert_eq!(t.token, "text/stdout-routing/first-line-token-change/open");
        assert_eq!(t.next_court, "cli-stdout-minimize");
        assert_eq!(t.blocks_claims, vec!["byte-identical stdout"]);
    }

    #[test]
    fn kappa_unknown_axis_gets_the_honest_generic_row() {
        // An externally served axis the router does not know: deterministic,
        // no fabricated minimizer target, and its open residual blocks
        // exactly the claims about that axis.
        let mut r = residual(ResidualKind::parse("wire").unwrap(), "malformed-input");
        r.axis = ObservableId::parse("dns.wire").unwrap();
        let t = kappa(&r, &Disposition::Open);
        assert_eq!(t.token, "wire/dns.wire-divergence/observed/open");
        assert_eq!(t.next_court, "none");
        assert_eq!(t.blocks_claims, vec!["malformed-input dns.wire parity"]);
    }

    #[test]
    fn kappa_reflects_disposition() {
        let r = residual(ResidualKind::exit(), "malformed-input");
        assert_eq!(
            kappa(&r, &fixed()).token,
            "exit/exit-class/class-change/fixed"
        );
        assert_eq!(kappa(&r, &fixed()).disposition, "fixed");
    }

    #[test]
    fn grammar_state_table() {
        assert_eq!(grammar_state(&Disposition::Open), "violation");
        assert_eq!(grammar_state(&fixed()), "recovery");
        let closed = |k| Disposition::Closed {
            kind: k,
            reason: "r".into(),
        };
        assert_eq!(
            grammar_state(&closed(ClosureKind::Intentional)),
            "intentional_divergence"
        );
        assert_eq!(
            grammar_state(&closed(ClosureKind::Environmental)),
            "boundary"
        );
        assert_eq!(
            grammar_state(&closed(ClosureKind::OracleVersion)),
            "boundary"
        );
        assert_eq!(grammar_state(&closed(ClosureKind::Harness)), "boundary");
        assert_eq!(grammar_state(&closed(ClosureKind::Unknown)), "unknown");
    }
}
