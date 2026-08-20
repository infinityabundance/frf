//! Deterministic endoduction: κ maps a raw residual to a typed token.
//!
//! This is the entire inference machinery of v0 — a lookup/classification
//! table, not a model. The table is auditable in one pass:
//!
//! | residual kind | token surface      | magnitude               | next_court              | blocks                              |
//! |---------------|--------------------|-------------------------|-------------------------|-------------------------------------|
//! | exit          | exit-class         | class-change            | cli-exit-minimize       | `{scope} exit parity`               |
//! | text          | diagnostic-routing | first-line-token-change | cli-diagnostic-minimize | byte-identical diagnostics          |
//!
//! Values follow Section 6 (token grammar example) and Section 12 (routing
//! targets and blocked-claim phrases) of the paper. κ is pure: the same
//! residual record always yields the same token, so receipts and on-disk
//! token files cannot drift.

use crate::model::*;

/// κ(r_raw, disposition) → (kind, surface, authority, magnitude, scope,
/// disposition, next_court). Pure: the same residual record and disposition
/// always yield the same token, so receipts and on-disk token files cannot
/// drift. The disposition is passed in because the observation record itself
/// is immutable; the current disposition is the projection of the residual's
/// event history.
pub fn kappa(r: &ResidualRecord, disposition: &Disposition) -> TokenRecord {
    let (surface, magnitude, next_court) = match r.kind {
        ResidualKind::Exit => ("exit-class", "class-change", "cli-exit-minimize"),
        ResidualKind::Text => (
            "diagnostic-routing",
            "first-line-token-change",
            "cli-diagnostic-minimize",
        ),
    };
    let blocks = match r.kind {
        ResidualKind::Exit => format!("{} exit parity", r.scope),
        ResidualKind::Text => "byte-identical diagnostics".to_string(),
    };
    let disposition = disposition.as_str().to_string();
    TokenRecord {
        schema_version: TOKEN_SCHEMA_VERSION.to_string(),
        residual_id: r.id.clone(),
        token: format!(
            "{}/{}/{}/{}",
            r.kind.as_str(),
            surface,
            magnitude,
            disposition
        ),
        kind: r.kind,
        surface: surface.to_string(),
        authority: r.authority.clone(),
        magnitude: magnitude.to_string(),
        scope: r.scope.clone(),
        disposition,
        next_court: next_court.to_string(),
        blocks_claims: vec![blocks],
    }
}

/// Appendix A `grammar_state` derived from disposition. Mapping table:
///
/// | disposition    | grammar_state       |
/// |----------------|---------------------|
/// | open           | violation           |
/// | fixed          | recovery            |
/// | intentional    | intentional_divergence |
/// | environmental  | boundary            |
/// | oracle_version | boundary            |
/// | harness        | boundary            |
/// | unknown        | unknown             |
pub fn grammar_state(disposition: &Disposition) -> &'static str {
    match disposition {
        Disposition::Open => "violation",
        Disposition::Fixed { .. } => "recovery",
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
        ResidualRecord {
            schema_version: SCHEMA_RESIDUAL.to_string(),
            id: format!("cli-{}-0001", kind.as_str()),
            court: "cli-malformed-input".to_string(),
            run: "run-cli-malformed-input-ab12cd34".to_string(),
            axis: match kind {
                ResidualKind::Exit => Axis::Exit,
                ResidualKind::Text => Axis::Stderr,
            },
            kind,
            surface: match kind {
                ResidualKind::Exit => None,
                ResidualKind::Text => Some("first-diagnostic-line".to_string()),
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
        let r = residual(ResidualKind::Exit, "malformed-input");
        assert_eq!(kappa(&r, &Disposition::Open), kappa(&r, &Disposition::Open));
    }

    #[test]
    fn kappa_exit_maps_to_exit_minimize() {
        let r = residual(ResidualKind::Exit, "malformed-input");
        let t = kappa(&r, &Disposition::Open);
        assert_eq!(t.token, "exit/exit-class/class-change/open");
        assert_eq!(t.next_court, "cli-exit-minimize");
        assert_eq!(t.blocks_claims, vec!["malformed-input exit parity"]);
        assert_eq!(t.authority, "ref-cli-1.8.2");
        assert_eq!(t.scope, "malformed-input");
    }

    #[test]
    fn kappa_text_maps_to_diagnostic_minimize() {
        let r = residual(ResidualKind::Text, "malformed-input");
        let t = kappa(&r, &Disposition::Open);
        assert_eq!(
            t.token,
            "text/diagnostic-routing/first-line-token-change/open"
        );
        assert_eq!(t.next_court, "cli-diagnostic-minimize");
        assert_eq!(t.blocks_claims, vec!["byte-identical diagnostics"]);
    }

    #[test]
    fn kappa_reflects_disposition() {
        let r = residual(ResidualKind::Exit, "malformed-input");
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
