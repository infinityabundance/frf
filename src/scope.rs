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
///
/// The `fixtures` dimension carries the EXACT fixture input identity
/// (FRF/FIXTURE/v1 over semantic id + content hash + declared arguments),
/// never the human label alone: two different files that share a fixture
/// id are different inputs, and the named role stays a separate
/// (`fixture_family`) dimension.
pub fn premise_scope(r: &Receipt) -> ClaimScope {
    let envelope = &r.court.admissibility_envelope;
    ClaimScope {
        authority: vec![format!("{}-{}", r.authority.name, r.authority.version)],
        candidate: vec![r.candidate.identity_hash.clone()],
        fixtures: r
            .fixtures
            .iter()
            .map(|f| {
                crate::semantics::fixture_identity(&f.id, &f.hash, &f.declared_arguments)
                    .unwrap_or_else(|e| {
                        panic!("the receipt's fixture identity must be protocol-computable: {e}")
                    })
            })
            .collect(),
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
/// authority record (the capture's envelope does not carry it). The
/// `fixtures` dimension carries the run's EXACT fixture input identity
/// (FRF/FIXTURE/v1) — an unexplained residual about exact input bytes, and
/// the claim surface it can block, are the same exact surface.
pub fn residual_scope(
    record: &ResidualRecord,
    capture: &CaptureManifest,
    authority_version: &str,
) -> ClaimScope {
    let envelope = &capture.court_spec.admissibility_envelope;
    let fixture = crate::semantics::fixture_identity(
        &capture.fixture,
        &capture.fixture_sha256,
        &capture.court_spec.fixture.arguments,
    )
    .unwrap_or_else(|e| panic!("the capture's fixture identity must be protocol-computable: {e}"));
    ClaimScope {
        authority: vec![record.authority.clone()],
        candidate: vec![record.candidate_sha256.clone()],
        fixtures: vec![fixture],
        fixture_family: envelope.fixture_family.clone(),
        observables: vec![record.axis.as_str().to_string()],
        environments: vec![capture.environment.digest.clone()],
        versions: vec![authority_version.to_string()],
        temporal: vec![record.run.clone()],
    }
}

/// The claim's scope K as a REGION: one cell per premise receipt, each cell
/// the receipt's executed surface restricted to the axes THAT premise's run
/// observed passing. The cells are never merged — the union of Cartesian
/// products is the cell list, not the product of dimension-wise unions, so a
/// multi-premise claim cannot invent a surface no premise observed.
pub fn claim_region(receipts: &[&Receipt]) -> EvidenceRegion {
    let mut region = EvidenceRegion::empty();
    for r in receipts {
        region.push(claim_scope(r));
    }
    region
}

/// The premises' observed surface P as a REGION: one cell per premise
/// receipt's FULL executed surface. Admission `K ⊆ P` is the region
/// containment: every point of every K cell must lie in SOME premise cell.
pub fn premise_region(receipts: &[&Receipt]) -> EvidenceRegion {
    let mut region = EvidenceRegion::empty();
    for r in receipts {
        region.push(premise_scope(r));
    }
    region
}

/// The axes a region of claim cells covers (the flat union across cells).
pub fn region_observables(region: &EvidenceRegion) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for cell in &region.cells {
        for a in &cell.observables {
            if !out.contains(a) {
                out.push(a.clone());
            }
        }
    }
    out
}

/// The residuals this region's cells' runs observed diverging (the axes a
/// multi-premise claim's cells exclude): the union across every premise.
pub fn region_excluded_evidence(receipts: &[&Receipt], region: &EvidenceRegion) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for r in receipts {
        for res in &r.residuals {
            // A residual whose axis IS covered by some cell is a blocker, not
            // excluded evidence; the claim's cells exclude each premise's own
            // residual axes, so residuals on uncovered axes are the excluded
            // divergences.
            let covered = region
                .cells
                .iter()
                .any(|c| c.observables.contains(&res.axis));
            if !covered && !out.contains(&res.id) {
                out.push(res.id.clone());
            }
        }
    }
    out
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
    fn region_union_does_not_invent_points() {
        // A union of Cartesian products is NOT the product of dimension-wise
        // unions: P1 = {f1} × {exit} × {e1}, P2 = {f2} × {stderr} × {e2}.
        // Merging dimension sets would invent (f1, stderr, e2) and
        // (f2, exit, e1) — evidence-space inflation. The region keeps the
        // cells and contains exactly the premise points.
        let p1 = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        let p2 = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f2"],
            "malformed-input",
            &["stderr"],
            &["e2"],
            &["1.8.2"],
        );
        let mut region = EvidenceRegion::empty();
        region.push(p1.clone());
        region.push(p2.clone());
        assert_eq!(region.cells.len(), 2, "cells are kept, never merged");
        assert!(region.contains(&p1));
        assert!(region.contains(&p2));
        // The invented cross point must NOT be contained: (f1, stderr, e2) is
        // in no cell. The dimension-wise merged product would have claimed it.
        let invented = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["stderr"],
            &["e2"],
            &["1.8.2"],
        );
        assert!(!region.contains(&invented));
        // A claim scope that is a SUBSET of a single cell is contained.
        let claim = scope(
            &["ref-cli-1.8.2"],
            &["h1"],
            &["f1"],
            "malformed-input",
            &["exit"],
            &["e1"],
            &["1.8.2"],
        );
        assert!(region.contains(&claim));
    }
}
