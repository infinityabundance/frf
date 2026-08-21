//! Claim scope derivation — where a claim's scope K and a residual's surface
//! come from. The algebra itself (intersection, containment, union) lives on
//! [`ClaimScope`]; this module derives the scopes from evidence.
//!
//! The paper's admission rule is `Scope(K) ⊆ Scope(P₁ ∪ … ∪ Pₙ)`: a claim may
//! assert parity only over the surface the premises actually observed. And a
//! blocking residual blocks exactly the claims whose scope intersects its
//! surface — product semantics over {authority, candidate, fixture, family,
//! observable, environment, version}, with `temporal` deliberately excluded:
//! an open divergence recorded by an earlier run about the same surface is
//! still an unexplained divergence about that surface.

use crate::model::*;

/// The executed surface of a receipt's run: the full region the premises
/// observed. A claim compiled from this receipt can never exceed it — the
/// compiler checks `premise_scope.contains(&k_scope)` literally.
pub fn premise_scope(r: &Receipt) -> ClaimScope {
    let envelope = &r.court.admissibility_envelope;
    ClaimScope {
        authority: vec![format!("{}-{}", r.authority.name, r.authority.version)],
        candidate: vec![r.candidate.identity_hash.clone()],
        fixtures: r.fixtures.iter().map(|f| f.id.clone()).collect(),
        fixture_family: envelope.fixture_family.clone(),
        observables: envelope.observables.clone(),
        environments: vec![r.environment.digest.clone()],
        versions: envelope.authority_versions.clone(),
        temporal: vec![r.run.clone()],
    }
}

/// The scope K of a claim compiled from a receipt: parity is asserted per
/// clean axis (an axis THIS run observed diverging is never parity from this
/// receipt, whatever the residual's disposition — a disposition links
/// history, it never rewrites an observation). Everything else is the
/// executed surface.
pub fn claim_scope(r: &Receipt) -> ClaimScope {
    let mut scope = premise_scope(r);
    scope.observables = r
        .observables
        .iter()
        .filter(|obs| !r.residuals.iter().any(|res| res.axis == obs.axis))
        .map(|obs| obs.axis.clone())
        .collect();
    scope
}

/// The surface of a residual: where the divergence was observed. Derived from
/// the immutable observation record and its run's capture — never from a
/// label a human could edit. The authority version comes from the admitted
/// authority record (the capture's envelope does not carry it).
pub fn residual_scope(
    record: &ResidualRecord,
    capture: &CaptureManifest,
    authority_version: &str,
) -> ClaimScope {
    let envelope = &capture.court_spec.admissibility_envelope;
    ClaimScope {
        authority: vec![record.authority.clone()],
        candidate: vec![record.candidate_sha256.clone()],
        fixtures: vec![capture.fixture.clone()],
        fixture_family: envelope.fixture_family.clone(),
        observables: vec![record.axis.as_str().to_string()],
        environments: vec![capture.environment.digest.clone()],
        versions: vec![authority_version.to_string()],
        temporal: vec![record.run.clone()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(
        authority: &[&str],
        candidate: &[&str],
        fixtures: &[&str],
        family: &str,
        observables: &[&str],
        environments: &[&str],
        versions: &[&str],
    ) -> ClaimScope {
        ClaimScope {
            authority: authority.iter().map(|s| s.to_string()).collect(),
            candidate: candidate.iter().map(|s| s.to_string()).collect(),
            fixtures: fixtures.iter().map(|s| s.to_string()).collect(),
            fixture_family: family.to_string(),
            observables: observables.iter().map(|s| s.to_string()).collect(),
            environments: environments.iter().map(|s| s.to_string()).collect(),
            versions: versions.iter().map(|s| s.to_string()).collect(),
            temporal: vec![],
        }
    }

    #[test]
    fn same_surface_intersects() {
        let a = scope(
            &["ref-cli-1.8.2"],
            &["c1"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        let b = scope(
            &["ref-cli-1.8.2"],
            &["c1"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        assert!(a.intersects(&b));
        assert!(b.intersects(&a));
    }

    #[test]
    fn different_candidate_does_not_intersect() {
        // The core of the resolution rule: a divergence observed against
        // candidate H0 does not block a claim about candidate H1, even on the
        // same axis, fixture, and environment.
        let residual = scope(
            &["ref-cli-1.8.2"],
            &["h0"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        let claim = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        assert!(!residual.intersects(&claim));
    }

    #[test]
    fn different_axis_does_not_intersect() {
        // An open stderr divergence blocks stderr claims, never exit claims.
        let residual = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["stderr"],
            &["e1"],
            &["1.8.2"],
        );
        let claim = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        assert!(!residual.intersects(&claim));
    }

    #[test]
    fn different_fixture_does_not_intersect() {
        // Fixture dimension: a divergence on fixture F1 blocks claims about
        // F1, never about F2 in the same family.
        let residual = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        let claim = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f2"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        assert!(!residual.intersects(&claim));
    }

    #[test]
    fn different_environment_does_not_intersect() {
        let residual = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        let claim = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e2"],
            &["1.8.2"],
        );
        assert!(!residual.intersects(&claim));
    }

    #[test]
    fn temporal_is_not_part_of_the_intersection() {
        // The same surface observed by a DIFFERENT run still intersects: an
        // earlier open divergence about the same surface blocks, wherever it
        // was recorded.
        let residual = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        let claim = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        assert!(residual.intersects(&claim));
    }

    #[test]
    fn containment_is_dimension_wise() {
        // Scope(K) ⊆ Scope(P): the claim may cover a SUBSET of the premises'
        // surface (clean axes only), never a superset.
        let premise = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1", "f2"],
            "malformed-input",
            &["exit", "stderr"],
            &["e1"],
            &["1.8.2"],
        );
        let claim = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        assert!(premise.contains(&claim));
        // And never a superset: an axis the premise did not declare.
        let overclaim = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["exit", "stdout"],
            &["e1"],
            &["1.8.2"],
        );
        assert!(!premise.contains(&overclaim));
        // A different candidate is outside the premise surface.
        let other_candidate = scope(
            &["ref-cli-1.8.2"],
            &["h2"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        assert!(!premise.contains(&other_candidate));
    }

    #[test]
    fn union_merges_dimension_sets() {
        let a = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        let b = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f2"],
            "malformed-input",
            &["stderr"],
            &["e2"],
            &["1.8.2"],
        );
        let u = a.union(&b);
        assert_eq!(u.fixtures, vec!["f1".to_string(), "f2".to_string()]);
        assert_eq!(
            u.observables,
            vec!["exit".to_string(), "stderr".to_string()]
        );
        assert_eq!(u.environments, vec!["e1".to_string(), "e2".to_string()]);
        assert!(u.contains(&a));
        assert!(u.contains(&b));
    }
}
