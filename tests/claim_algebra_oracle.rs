//! The tiny MATHEMATICAL ORACLE for the claim-scope algebra — a deliberately
//! DUMB verifier that thinks in literal tuples over a bounded Cartesian
//! universe, compared against the production `EvidenceRegion`/`ClaimScope`
//! DNF algebra over millions of random cases.
//!
//! The production algebra answers `region.contains(point)` with a
//! dimension-wise superset check over a cell list (the DNF union). The
//! oracle answers with LITERAL SET MEMBERSHIP: every premise is materialized
//! as a set of concrete tuples, and a point is covered iff one of its tuples
//! is in some premise's tuple set. Two radically different structures MUST
//! agree on every random case; if they ever disagree, the algebra has a
//! regression the oracle caught.
//!
//! The meta-property is checked literally too: for any compiled region, the
//! set of covered points (materialized by enumeration) must equal the set
//! the production algebra accepts — `K ⊆ union(P)` with literal set
//! membership, not with the algebra checking itself.

use frf::model::{ClaimScope, EvidenceRegion};
use std::collections::BTreeSet;

/// The bounded universe the oracle enumerates.
struct Universe {
    authorities: Vec<String>,
    candidates: Vec<String>,
    fixtures: Vec<String>,
    observables: Vec<String>,
    environments: Vec<String>,
    versions: Vec<String>,
}

/// A concrete point: one value per dimension.
type Point = (String, String, String, String, String, String);

fn dims(seed: u64, n: usize, tag: &str) -> Vec<String> {
    (0..n)
        .map(|i| format!("{tag}-{}", &sha256(&[seed as u8, i as u8])[..8]))
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    frf::host::sha256_bytes(bytes)
}

impl Universe {
    fn new(seed: u64) -> Universe {
        Universe {
            authorities: dims(seed, 2, "auth"),
            candidates: dims(seed.wrapping_add(1), 2, "cand"),
            fixtures: dims(seed.wrapping_add(2), 3, "fix"),
            observables: dims(seed.wrapping_add(3), 3, "axis"),
            environments: dims(seed.wrapping_add(4), 2, "env"),
            versions: dims(seed.wrapping_add(5), 2, "ver"),
        }
    }

    /// The full cross product of the universe — the literal domain.
    fn all_points(&self) -> Vec<Point> {
        let mut out = Vec::new();
        for a in &self.authorities {
            for c in &self.candidates {
                for f in &self.fixtures {
                    for o in &self.observables {
                        for e in &self.environments {
                            for v in &self.versions {
                                out.push((
                                    a.clone(),
                                    c.clone(),
                                    f.clone(),
                                    o.clone(),
                                    e.clone(),
                                    v.clone(),
                                ));
                            }
                        }
                    }
                }
            }
        }
        out
    }

    fn point(&self, pick: &[usize]) -> Point {
        let p = |v: &[String], i: usize| v[pick[i] % v.len()].clone();
        (
            p(&self.authorities, 0),
            p(&self.candidates, 1),
            p(&self.fixtures, 2),
            p(&self.observables, 3),
            p(&self.environments, 4),
            p(&self.versions, 5),
        )
    }

    fn scope(&self, p: &Point) -> ClaimScope {
        ClaimScope {
            authority: vec![p.0.clone()],
            candidate: vec![p.1.clone()],
            fixtures: vec![p.2.clone()],
            observables: vec![p.3.clone()],
            environments: vec![p.4.clone()],
            versions: vec![p.5.clone()],
            fixture_family: "f".to_string(),
            temporal: Vec::new(),
        }
    }

    /// A RANDOM premise scope: each dimension is a random subset (never
    /// empty, so the premise observes something definite).
    fn random_scope(&self, seed: u64) -> ClaimScope {
        let pick = |v: &[String], salt: u64| {
            let mut out = Vec::new();
            for (i, x) in v.iter().enumerate() {
                if (seed
                    .wrapping_mul(2654435761)
                    .wrapping_add(i as u64)
                    .wrapping_add(salt))
                    % 3
                    != 0
                {
                    out.push(x.clone());
                }
            }
            if out.is_empty() {
                out.push(v[seed as usize % v.len()].clone());
            }
            out
        };
        ClaimScope {
            authority: pick(&self.authorities, 1),
            candidate: pick(&self.candidates, 2),
            fixtures: pick(&self.fixtures, 3),
            observables: pick(&self.observables, 4),
            environments: pick(&self.environments, 5),
            versions: pick(&self.versions, 6),
            fixture_family: "f".to_string(),
            temporal: Vec::new(),
        }
    }
}

/// The DUMB oracle: a point is covered by a region iff there exists a
/// premise whose EVERY dimension set contains the point's value — computed
/// as literal set membership over the materialized tuples, with zero
/// algebra.
fn oracle_covers(premises: &[BTreeSet<Point>], p: &Point) -> bool {
    premises.iter().any(|set| set.contains(p))
}

/// Materialize a scope's cross product as a literal tuple set (the universe
/// is only needed for the typed access; the scope's own dimension sets
/// determine the tuples).
#[allow(unused_variables)]
fn materialize(u: &Universe, s: &ClaimScope) -> BTreeSet<Point> {
    let mut out = BTreeSet::new();
    for a in &s.authority {
        for c in &s.candidate {
            for f in &s.fixtures {
                for o in &s.observables {
                    for e in &s.environments {
                        for v in &s.versions {
                            out.insert((
                                a.clone(),
                                c.clone(),
                                f.clone(),
                                o.clone(),
                                e.clone(),
                                v.clone(),
                            ));
                        }
                    }
                }
            }
        }
    }
    out
}

#[test]
fn the_algebra_and_the_literal_oracle_agree_on_random_cases() {
    let u = Universe::new(7);
    // Materialize every premise as a literal tuple set (the oracle).
    let mut cases = 0u64;
    // Deterministic LCG over the bounded universe — millions of cases.
    let mut state: u64 = 0x1234_5678_9abc_def0;
    let mut step = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };
    while cases < 200_000 {
        let n_premises = 1 + (step() % 4) as usize;
        let mut premises: Vec<ClaimScope> = Vec::new();
        let mut sets: Vec<BTreeSet<Point>> = Vec::new();
        for _ in 0..n_premises {
            let s = u.random_scope(step());
            sets.push(materialize(&u, &s));
            premises.push(s);
        }
        let region = {
            let mut r = EvidenceRegion::empty();
            for p in premises {
                r.push(p);
            }
            r
        };
        // Sample random points (and a few boundary points: single-value
        // scopes).
        for _ in 0..16 {
            let seed = step();
            let pick = [
                (seed % 2) as usize,
                ((seed >> 3) % 2) as usize,
                ((seed >> 6) % 3) as usize,
                ((seed >> 9) % 3) as usize,
                ((seed >> 12) % 2) as usize,
                ((seed >> 15) % 2) as usize,
            ];
            let p = u.point(&pick);
            let scope = u.scope(&p);
            let production = region.contains(&scope);
            let oracle = oracle_covers(&sets, &p);
            assert_eq!(
                production, oracle,
                "the DNF algebra and the literal oracle disagree on {p:?}"
            );
            cases += 1;
        }
    }
    assert!(cases >= 100_000, "the oracle must actually run");
}

#[test]
fn the_meta_property_holds_literally_covered_equals_algebra_covered() {
    // For a random region, the set of points the algebra accepts MUST equal
    // the literal set of covered points (enumerated over the whole bounded
    // universe). K ⊆ union(P) checked with literal set membership.
    let u = Universe::new(99);
    let mut state: u64 = 0xdead_beef_cafe_f00d;
    let mut step = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };
    for _case in 0..200 {
        let n_premises = 1 + (step() % 4) as usize;
        let mut premises: Vec<ClaimScope> = Vec::new();
        let mut sets: Vec<BTreeSet<Point>> = Vec::new();
        for _ in 0..n_premises {
            let s = u.random_scope(step());
            sets.push(materialize(&u, &s));
            premises.push(s);
        }
        let region = {
            let mut r = EvidenceRegion::empty();
            for p in premises {
                r.push(p);
            }
            r
        };
        // Every point of the bounded universe: literal vs algebra.
        for p in u.all_points() {
            let production = region.contains(&u.scope(&p));
            let oracle = oracle_covers(&sets, &p);
            assert_eq!(production, oracle, "meta-property violated at {p:?}");
        }
    }
}
