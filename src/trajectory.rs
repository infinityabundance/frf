//! Residual trajectory classification — the executable form of drift/slew.
//!
//! A trajectory is an ordered series of observations of one residual LINEAGE
//! over a declared coordinate system (`repeat_index`, `candidate_revision`,
//! `authority_version`, `environment`, `time`). Trajectories are DERIVED from
//! an [`ExecutionSeries`]; a run never knows which experiment references it.
//!
//! The classification is a DETERMINISTIC TABLE, not a model — auditable in
//! one pass. Given the observed pattern `o[1..=N]` (at least one true) with
//! `T = { i | o[i] }`:
//!
//! ```text
//! |T| == N                     -> drift=persistent,  slew=stable,
//!                                 localization=none,  bands=1
//! T contiguous:
//!     first == 1              -> drift=transient,   slew=abrupt,
//!                                 localization=start (boundary-localized)
//!     last  == N              -> drift=transient,   slew=abrupt,
//!                                 localization=end   (boundary-localized)
//!     otherwise               -> drift=transient,   slew=burst,
//!                                 localization=interior
//! T non-contiguous:
//!     1 ∈ T  and  N ∈ T       -> drift=recurrent,   slew=recurrent,
//!                                 localization=both (2+ bands =
//!                                 version-stratified along a version axis)
//!     otherwise               -> drift=transient,   slew=recurrent,
//!                                 localization by which ends are touched
//! ```
//!
//! `bands` is the number of contiguous observed runs: 1 for the
//! persistent/abrupt/burst patterns, 2+ for the recurrent/stratified ones.
//! The paper's `boundary-localized` is the start/end localization;
//! `version-stratified` is the 2+-band pattern along an authority-version
//! axis; `gradual` needs a magnitude dimension (presence is binary) and is
//! deliberately not claimed.

use crate::error::{FrfError, Result};
use crate::model::{TrajectoryDerivation, TrajectoryDrift, TrajectoryLocalization, TrajectorySlew};

/// Classify an ordered observation pattern over any axis. Requires at least
/// one observation: a trajectory only exists for a divergence that was
/// observed at least once.
pub fn classify(observed: &[bool]) -> Result<TrajectoryDerivation> {
    if observed.is_empty() {
        return Err(FrfError::new(
            "cannot classify an empty series — a trajectory needs at least one observation",
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
            "cannot classify a series with no observations",
        ));
    }
    let first = t.first().copied().unwrap();
    let last = t.last().copied().unwrap();
    let bands = contiguous_bands(&t);
    let contiguous = last - first + 1 == t.len();
    let drift;
    let (slew, localization) = if t.len() == n {
        drift = TrajectoryDrift::Persistent;
        (TrajectorySlew::Stable, TrajectoryLocalization::None_)
    } else if contiguous {
        drift = TrajectoryDrift::Transient;
        if first == 0 && last == n - 1 {
            unreachable!("a contiguous band covering both ends with |T| < n is impossible");
        } else if first == 0 {
            (TrajectorySlew::Abrupt, TrajectoryLocalization::Start)
        } else if last == n - 1 {
            (TrajectorySlew::Abrupt, TrajectoryLocalization::End)
        } else {
            (TrajectorySlew::Burst, TrajectoryLocalization::Interior)
        }
    } else if first == 0 && last == n - 1 {
        drift = TrajectoryDrift::Recurrent;
        (TrajectorySlew::Recurrent, TrajectoryLocalization::Both)
    } else {
        drift = TrajectoryDrift::Transient;
        let localization = if first == 0 {
            TrajectoryLocalization::Start
        } else if last == n - 1 {
            TrajectoryLocalization::End
        } else {
            TrajectoryLocalization::Interior
        };
        (TrajectorySlew::Recurrent, localization)
    };
    Ok(TrajectoryDerivation {
        drift,
        slew,
        localization,
        bands,
    })
}

/// The number of contiguous observed bands in the index set.
fn contiguous_bands(t: &[usize]) -> u32 {
    let mut bands = 1;
    for w in t.windows(2) {
        if w[1] != w[0] + 1 {
            bands += 1;
        }
    }
    bands
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dr(observed: &[bool]) -> TrajectoryDerivation {
        classify(observed).unwrap()
    }

    #[test]
    fn all_observed_is_persistent_and_stable() {
        let d = dr(&[true, true, true]);
        assert_eq!(d.drift, TrajectoryDrift::Persistent);
        assert_eq!(d.slew, TrajectorySlew::Stable);
        assert_eq!(d.localization, TrajectoryLocalization::None_);
        assert_eq!(d.bands, 1);
    }

    #[test]
    fn first_only_is_a_boundary_localized_cessation() {
        let d = dr(&[true, false, false]);
        assert_eq!(d.drift, TrajectoryDrift::Transient);
        assert_eq!(d.slew, TrajectorySlew::Abrupt);
        assert_eq!(d.localization, TrajectoryLocalization::Start);
        assert_eq!(d.bands, 1);
    }

    #[test]
    fn last_only_is_a_boundary_localized_onset() {
        let d = dr(&[false, false, true]);
        assert_eq!(d.drift, TrajectoryDrift::Transient);
        assert_eq!(d.slew, TrajectorySlew::Abrupt);
        assert_eq!(d.localization, TrajectoryLocalization::End);
    }

    #[test]
    fn interior_window_is_a_burst() {
        let d = dr(&[false, true, true, false, false]);
        assert_eq!(d.drift, TrajectoryDrift::Transient);
        assert_eq!(d.slew, TrajectorySlew::Burst);
        assert_eq!(d.localization, TrajectoryLocalization::Interior);
        assert_eq!(d.bands, 1);
    }

    #[test]
    fn came_back_is_recurrent_and_stratified() {
        let d = dr(&[true, false, true, false, true]);
        assert_eq!(d.drift, TrajectoryDrift::Recurrent);
        assert_eq!(d.slew, TrajectorySlew::Recurrent);
        assert_eq!(d.localization, TrajectoryLocalization::Both);
        assert_eq!(d.bands, 3);
    }

    #[test]
    fn non_contiguous_away_from_both_ends_is_interior_stratified() {
        // The divergence appears in two interior windows: version-stratified
        // away from the boundaries.
        let d = dr(&[false, true, false, true, false]);
        assert_eq!(d.drift, TrajectoryDrift::Transient);
        assert_eq!(d.slew, TrajectorySlew::Recurrent);
        assert_eq!(d.localization, TrajectoryLocalization::Interior);
        assert_eq!(d.bands, 2);
    }

    #[test]
    fn two_repetition_patterns() {
        assert_eq!(dr(&[true]).drift, TrajectoryDrift::Persistent);
        assert_eq!(dr(&[true]).slew, TrajectorySlew::Stable);
        assert_eq!(dr(&[true, true]).drift, TrajectoryDrift::Persistent);
        let d = dr(&[false, true]);
        assert_eq!(d.drift, TrajectoryDrift::Transient);
        assert_eq!(d.slew, TrajectorySlew::Abrupt);
        assert_eq!(d.localization, TrajectoryLocalization::End);
    }

    #[test]
    fn empty_or_all_false_series_are_refused() {
        assert!(classify(&[]).is_err());
        assert!(classify(&[false, false]).is_err());
    }

    #[test]
    fn the_vocabulary_is_closed_and_distinct() {
        assert_eq!(TrajectoryDrift::ALL.len(), 3);
        assert_eq!(TrajectorySlew::ALL.len(), 4);
        assert_eq!(TrajectoryLocalization::ALL.len(), 5);
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
        for (i, a) in TrajectoryLocalization::ALL.iter().enumerate() {
            for (j, b) in TrajectoryLocalization::ALL.iter().enumerate() {
                assert_eq!(i == j, a.as_str() == b.as_str());
            }
        }
    }
}
