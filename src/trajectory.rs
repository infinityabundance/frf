//! Residual trajectory classification — the executable form of drift/slew.
//!
//! A trajectory is an ordered series of observations of one residual
//! FINGERPRINT over a coordinate system. v0.1.17 executes the `repeat_index`
//! axis only (`frf court run --repeat N`); the other axes from the paper
//! (candidate_revision, authority_version, environment, fixture_reduction,
//! time) become executable as those protocol objects exist.
//!
//! The classification is a DETERMINISTIC TABLE, not a model — auditable in
//! one pass. Given the observed pattern `o[1..=N]` (at least one true):
//!
//! ```text
//! |T| == N                     -> drift=persistent, slew=stable
//! T contiguous:
//!     1 ∈ T  or  N ∈ T         -> drift=transient,  slew=abrupt   (one boundary)
//!     otherwise                -> drift=transient,  slew=burst    (interior window)
//! T non-contiguous:
//!     1 ∈ T  and  N ∈ T        -> drift=recurrent,  slew=recurrent (came back)
//!     otherwise                -> drift=transient,  slew=recurrent
//! ```
//!
//! where `T = { i | o[i] }`. Vocabulary mapping to the paper's:
//! `persistent`/`transient`/`recurrent` (drift) and `stable`/`abrupt`/
//! `burst`/`recurrent` (slew) are the repeat-axis values; `gradual`,
//! `version-stratified`, and `boundary-localized` belong to the
//! candidate/authority/time axes, which are future work. The paper's own
//! restraint holds here too: N repetitions establish the repeat axis only,
//! and never more.

use crate::error::{FrfError, Result};
use crate::model::{TrajectoryDerivation, TrajectoryDrift, TrajectorySlew};

/// Classify a repeat-axis observation pattern. Requires at least one
/// observation: a trajectory only exists for a divergence that was observed
/// at least once.
pub fn classify_repeat(observed: &[bool]) -> Result<TrajectoryDerivation> {
    if observed.is_empty() {
        return Err(FrfError::new(
            "cannot classify an empty repeat series — a trajectory needs at least one observation",
        ));
    }
    let n = observed.len();
    let t: Vec<usize> = observed
        .iter()
        .enumerate()
        .filter(|(_, o)| **o)
        .map(|(i, _)| i)
        .collect();
    if t.is_empty() {
        return Err(FrfError::new(
            "cannot classify a repeat series with no observations",
        ));
    }
    if t.len() == n {
        return Ok(TrajectoryDerivation {
            drift: TrajectoryDrift::Persistent,
            slew: TrajectorySlew::Stable,
        });
    }
    let contiguous = t.last().unwrap() - t.first().unwrap() + 1 == t.len();
    if contiguous {
        if t.first() == Some(&0) || t.last() == Some(&(n - 1)) {
            Ok(TrajectoryDerivation {
                drift: TrajectoryDrift::Transient,
                slew: TrajectorySlew::Abrupt,
            })
        } else {
            Ok(TrajectoryDerivation {
                drift: TrajectoryDrift::Transient,
                slew: TrajectorySlew::Burst,
            })
        }
    } else if t.first() == Some(&0) && t.last() == Some(&(n - 1)) {
        Ok(TrajectoryDerivation {
            drift: TrajectoryDrift::Recurrent,
            slew: TrajectorySlew::Recurrent,
        })
    } else {
        Ok(TrajectoryDerivation {
            drift: TrajectoryDrift::Transient,
            slew: TrajectorySlew::Recurrent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dr(observed: &[bool]) -> TrajectoryDerivation {
        classify_repeat(observed).unwrap()
    }

    #[test]
    fn all_observed_is_persistent_and_stable() {
        let d = dr(&[true, true, true]);
        assert_eq!(d.drift, TrajectoryDrift::Persistent);
        assert_eq!(d.slew, TrajectorySlew::Stable);
    }

    #[test]
    fn first_only_is_an_abrupt_cessation() {
        let d = dr(&[true, false, false]);
        assert_eq!(d.drift, TrajectoryDrift::Transient);
        assert_eq!(d.slew, TrajectorySlew::Abrupt);
    }

    #[test]
    fn last_only_is_an_abrupt_onset() {
        let d = dr(&[false, false, true]);
        assert_eq!(d.drift, TrajectoryDrift::Transient);
        assert_eq!(d.slew, TrajectorySlew::Abrupt);
    }

    #[test]
    fn interior_window_is_a_burst() {
        let d = dr(&[false, true, true, false, false]);
        assert_eq!(d.drift, TrajectoryDrift::Transient);
        assert_eq!(d.slew, TrajectorySlew::Burst);
    }

    #[test]
    fn came_back_is_recurrent() {
        let d = dr(&[true, false, true, false, true]);
        assert_eq!(d.drift, TrajectoryDrift::Recurrent);
        assert_eq!(d.slew, TrajectorySlew::Recurrent);
    }

    #[test]
    fn two_repetition_patterns() {
        assert_eq!(dr(&[true]).drift, TrajectoryDrift::Persistent);
        assert_eq!(dr(&[true]).slew, TrajectorySlew::Stable);
        assert_eq!(dr(&[true, true]).drift, TrajectoryDrift::Persistent);
        let d = dr(&[false, true]);
        assert_eq!(d.drift, TrajectoryDrift::Transient);
        assert_eq!(d.slew, TrajectorySlew::Abrupt);
    }

    #[test]
    fn empty_or_all_false_series_are_refused() {
        assert!(classify_repeat(&[]).is_err());
        assert!(classify_repeat(&[false, false]).is_err());
    }

    #[test]
    fn the_vocabulary_is_closed_and_distinct() {
        assert_eq!(TrajectoryDrift::ALL.len(), 3);
        assert_eq!(TrajectorySlew::ALL.len(), 4);
        for (i, a) in TrajectoryDrift::ALL.iter().enumerate() {
            for (j, b) in TrajectoryDrift::ALL.iter().enumerate() {
                assert_eq!(i == j, a.as_str() == b.as_str());
            }
        }
        for (i, a) in TrajectorySlew::ALL.iter().enumerate() {
            for (j, b) in TrajectorySlew::ALL.iter().enumerate() {
                assert_eq!(i == j, a.as_str() == b.as_str());
            }
        }
    }
}
