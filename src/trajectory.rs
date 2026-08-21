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
//! |T| == N                     -> drift=persistent,         slew=stable,
//!                                 localization=none,          bands=1
//! T contiguous:
//!     first == 1              -> drift=boundary-localized,  slew=abrupt,
//!                                 localization=start (cessation)
//!     last  == N              -> drift=boundary-localized,  slew=abrupt,
//!                                 localization=end   (onset)
//!     otherwise               -> drift=transient,           slew=burst,
//!                                 localization=interior
//! T non-contiguous:
//!     version/revision axis   -> drift=version-stratified,  slew=recurrent,
//!                                 localization by which ends are touched
//!     (bands >= 2)                (the divergence recurs across a ladder)
//!     1 ∈ T  and  N ∈ T       -> drift=recurrent,           slew=recurrent,
//!                                 localization=both
//!     otherwise               -> drift=transient,           slew=recurrent,
//!                                 localization by which ends are touched
//! ```
//!
//! `bands` is the number of contiguous observed runs: 1 for the
//! persistent/boundary-localized/burst patterns, 2+ for the recurrent/
//! stratified ones.
//!
//! v4 (0.1.37) adds the MAGNITUDE dimension: when the axis's comparator
//! declares a deterministic distance measure, each observation carries a
//! magnitude (the degree of divergence at that point) and the derivation
//! carries the `trend` of those magnitudes in coordinate order. `gradual` is
//! claimed EXACTLY when the trend is monotonic (increasing or decreasing) — a
//! ramp, not a step. An axis with no declared measure, or a series with too
//! few observed points, honestly yields `trend=unknown` and never claims
//! gradual (fail-closed: presence is binary, degree is the measure).

use crate::error::{FrfError, Result};
use crate::model::{
    TrajectoryDerivation, TrajectoryDrift, TrajectoryLocalization, TrajectorySlew, TrajectoryTrend,
};

/// The ordered stratification axes: two or more observed bands along one of
/// these is `version-stratified` (the divergence recurs across a version/
/// revision ladder). Repeat, environment, and time are not stratification
/// axes: a non-contiguous pattern there is recurrent/cyclic nondeterminism,
/// not version stratification.
pub const STRATIFIED_AXES: &[&str] = &["authority_version", "candidate_revision"];

/// Classify an ordered observation pattern over any axis. Requires at least
/// one observation: a trajectory only exists for a divergence that was
/// observed at least once.
///
/// - `observed[i]` — whether the lineage was observed at point i;
/// - `coordinate_system` — the axis the points are ordered over;
/// - `magnitudes[i]` — the per-point divergence degree, when the axis's
///   comparator declares a measure (absent elsewhere);
/// - `magnitude_kind` — the declared measure name, or `none`.
pub fn classify(
    observed: &[bool],
    coordinate_system: &str,
    magnitudes: &[Option<String>],
    magnitude_kind: &str,
) -> Result<TrajectoryDerivation> {
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
        if first == 0 && last == n - 1 {
            unreachable!("a contiguous band covering both ends with |T| < n is impossible");
        } else if first == 0 {
            drift = TrajectoryDrift::BoundaryLocalized;
            (TrajectorySlew::Abrupt, TrajectoryLocalization::Start)
        } else if last == n - 1 {
            drift = TrajectoryDrift::BoundaryLocalized;
            (TrajectorySlew::Abrupt, TrajectoryLocalization::End)
        } else {
            drift = TrajectoryDrift::Transient;
            (TrajectorySlew::Burst, TrajectoryLocalization::Interior)
        }
    } else if bands >= 2 && STRATIFIED_AXES.contains(&coordinate_system) {
        // The divergence recurs across a version/revision ladder: stratified.
        drift = TrajectoryDrift::VersionStratified;
        let localization = if first == 0 && last == n - 1 {
            TrajectoryLocalization::Both
        } else if first == 0 {
            TrajectoryLocalization::Start
        } else if last == n - 1 {
            TrajectoryLocalization::End
        } else {
            TrajectoryLocalization::Interior
        };
        (TrajectorySlew::Recurrent, localization)
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
    let (trend, slew) = magnitude(observed, magnitudes, magnitude_kind, slew);
    Ok(TrajectoryDerivation {
        drift,
        slew,
        localization,
        bands: bands.to_string(),
        trend,
        magnitude_kind: magnitude_kind.to_string(),
    })
}

/// The magnitude trend over the observed points (in coordinate order), and
/// the slew it licenses: `gradual` exactly when the trend is monotonic.
/// No declared measure, or too few observed points, yields `unknown` and
/// keeps the presence-derived slew. Only OBSERVED points carry a magnitude
/// (an unobserved point has no divergence to measure); the filter reads the
/// observed flags, never the magnitude presence alone.
fn magnitude(
    observed: &[bool],
    magnitudes: &[Option<String>],
    magnitude_kind: &str,
    slew: TrajectorySlew,
) -> (TrajectoryTrend, TrajectorySlew) {
    if magnitude_kind == "none" {
        return (TrajectoryTrend::Unknown, slew);
    }
    let values: Vec<i64> = observed
        .iter()
        .zip(magnitudes.iter())
        .filter(|(o, _)| **o)
        .filter_map(|(_, m)| m.as_deref().and_then(|v| v.parse::<i64>().ok()))
        .collect();
    // A trend needs at least THREE observed magnitudes: with two points a
    // monotone step cannot be distinguished from a jump, and non-monotonicity
    // cannot be falsified. Fail-closed: fewer observations stay unknown.
    if values.len() < 3 {
        return (TrajectoryTrend::Unknown, slew);
    }
    let mut increasing = false;
    let mut decreasing = false;
    for w in values.windows(2) {
        if w[1] > w[0] {
            increasing = true;
        } else if w[1] < w[0] {
            decreasing = true;
        }
    }
    let trend = if !increasing && !decreasing {
        TrajectoryTrend::Flat
    } else if increasing && !decreasing {
        TrajectoryTrend::Increasing
    } else if !increasing && decreasing {
        TrajectoryTrend::Decreasing
    } else {
        TrajectoryTrend::NonMonotonic
    };
    let slew = match trend {
        TrajectoryTrend::Increasing | TrajectoryTrend::Decreasing => TrajectorySlew::Gradual,
        _ => slew,
    };
    (trend, slew)
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

    fn dr(
        observed: &[bool],
        coord: &str,
        magnitudes: &[Option<String>],
        kind: &str,
    ) -> TrajectoryDerivation {
        classify(observed, coord, magnitudes, kind).unwrap()
    }

    fn mags(v: &[i64]) -> Vec<Option<String>> {
        v.iter().map(|m| Some(m.to_string())).collect()
    }

    fn none(n: usize) -> Vec<Option<String>> {
        vec![None; n]
    }

    #[test]
    fn all_observed_is_persistent_and_stable() {
        let d = dr(&[true, true, true], "repeat_index", &none(3), "none");
        assert_eq!(d.drift, TrajectoryDrift::Persistent);
        assert_eq!(d.slew, TrajectorySlew::Stable);
        assert_eq!(d.localization, TrajectoryLocalization::None_);
        assert_eq!(d.bands, "1");
        assert_eq!(d.trend, TrajectoryTrend::Unknown);
    }

    #[test]
    fn first_only_is_a_boundary_localized_cessation() {
        let d = dr(
            &[true, false, false],
            "candidate_revision",
            &none(3),
            "none",
        );
        assert_eq!(d.drift, TrajectoryDrift::BoundaryLocalized);
        assert_eq!(d.slew, TrajectorySlew::Abrupt);
        assert_eq!(d.localization, TrajectoryLocalization::Start);
        assert_eq!(d.bands, "1");
    }

    #[test]
    fn last_only_is_a_boundary_localized_onset() {
        let d = dr(&[false, false, true], "authority_version", &none(3), "none");
        assert_eq!(d.drift, TrajectoryDrift::BoundaryLocalized);
        assert_eq!(d.slew, TrajectorySlew::Abrupt);
        assert_eq!(d.localization, TrajectoryLocalization::End);
    }

    #[test]
    fn interior_window_is_a_burst() {
        let d = dr(&[false, true, true, false, false], "time", &none(5), "none");
        assert_eq!(d.drift, TrajectoryDrift::Transient);
        assert_eq!(d.slew, TrajectorySlew::Burst);
        assert_eq!(d.localization, TrajectoryLocalization::Interior);
        assert_eq!(d.bands, "1");
    }

    #[test]
    fn came_back_is_recurrent_on_non_stratified_axes() {
        let d = dr(
            &[true, false, true, false, true],
            "repeat_index",
            &none(5),
            "none",
        );
        assert_eq!(d.drift, TrajectoryDrift::Recurrent);
        assert_eq!(d.slew, TrajectorySlew::Recurrent);
        assert_eq!(d.localization, TrajectoryLocalization::Both);
        assert_eq!(d.bands, "3");
    }

    #[test]
    fn multi_band_pattern_on_a_version_axis_is_version_stratified() {
        let d = dr(
            &[false, true, false, true, false],
            "authority_version",
            &none(5),
            "none",
        );
        assert_eq!(d.drift, TrajectoryDrift::VersionStratified);
        assert_eq!(d.slew, TrajectorySlew::Recurrent);
        assert_eq!(d.localization, TrajectoryLocalization::Interior);
        assert_eq!(d.bands, "2");
    }

    #[test]
    fn multi_band_pattern_on_a_revision_axis_is_version_stratified() {
        let d = dr(
            &[true, false, true, true, false],
            "candidate_revision",
            &none(5),
            "none",
        );
        assert_eq!(d.drift, TrajectoryDrift::VersionStratified);
        assert_eq!(d.bands, "2");
    }

    #[test]
    fn the_same_pattern_on_environment_is_recurrent_not_stratified() {
        let d = dr(
            &[false, true, false, true, false],
            "environment",
            &none(5),
            "none",
        );
        assert_eq!(d.drift, TrajectoryDrift::Transient);
        assert_eq!(d.slew, TrajectorySlew::Recurrent);
        assert_eq!(d.localization, TrajectoryLocalization::Interior);
    }

    #[test]
    fn non_contiguous_away_from_both_ends_is_transient_recurrent() {
        let d = dr(&[false, true, false, true, false], "time", &none(5), "none");
        assert_eq!(d.drift, TrajectoryDrift::Transient);
        assert_eq!(d.slew, TrajectorySlew::Recurrent);
        assert_eq!(d.localization, TrajectoryLocalization::Interior);
        assert_eq!(d.bands, "2");
    }

    #[test]
    fn a_ramp_is_gradual() {
        // The divergence is present everywhere, but its degree grows: a
        // gradual ramp, not a step.
        let d = dr(
            &[true, true, true, true],
            "candidate_revision",
            &mags(&[1, 2, 3, 4]),
            "line-edit-distance",
        );
        assert_eq!(d.drift, TrajectoryDrift::Persistent);
        assert_eq!(d.slew, TrajectorySlew::Gradual);
        assert_eq!(d.trend, TrajectoryTrend::Increasing);
    }

    #[test]
    fn a_taper_is_gradual() {
        // Present at every point, degree shrinking to zero: a gradual
        // cessation ramp.
        let d = dr(
            &[true, true, true, true],
            "time",
            &mags(&[4, 3, 2, 1]),
            "line-edit-distance",
        );
        assert_eq!(d.slew, TrajectorySlew::Gradual);
        assert_eq!(d.trend, TrajectoryTrend::Decreasing);
    }

    #[test]
    fn flat_magnitude_is_not_gradual() {
        let d = dr(
            &[true, true, true],
            "repeat_index",
            &mags(&[2, 2, 2]),
            "exit-code-distance",
        );
        assert_eq!(d.drift, TrajectoryDrift::Persistent);
        assert_eq!(d.slew, TrajectorySlew::Stable);
        assert_eq!(d.trend, TrajectoryTrend::Flat);
    }

    #[test]
    fn non_monotonic_magnitude_is_not_gradual() {
        let d = dr(
            &[true, true, true, true],
            "time",
            &mags(&[1, 3, 2, 4]),
            "line-edit-distance",
        );
        assert_eq!(d.slew, TrajectorySlew::Stable);
        assert_eq!(d.trend, TrajectoryTrend::NonMonotonic);
    }

    #[test]
    fn too_few_observed_points_cannot_claim_a_trend() {
        // Two points can move, but cannot establish a trend: unknown.
        let d = dr(
            &[true, false, true],
            "candidate_revision",
            &mags(&[1, 0, 3]),
            "line-edit-distance",
        );
        assert_eq!(d.trend, TrajectoryTrend::Unknown);
        assert_eq!(d.slew, TrajectorySlew::Recurrent);
        // A boundary-localized onset with one observed point: no trend.
        let d = dr(
            &[false, true],
            "authority_version",
            &mags(&[0, 5]),
            "exit-code-distance",
        );
        assert_eq!(d.trend, TrajectoryTrend::Unknown);
    }

    #[test]
    fn boundary_localized_with_magnitude_can_be_gradual_onset() {
        // Absent early, then present with an increasing degree across enough
        // points to establish a trend: a gradual onset at the end boundary.
        let d = dr(
            &[false, true, true, true],
            "time",
            &[None, Some("1".into()), Some("3".into()), Some("5".into())],
            "line-edit-distance",
        );
        assert_eq!(d.drift, TrajectoryDrift::BoundaryLocalized);
        assert_eq!(d.slew, TrajectorySlew::Gradual);
        assert_eq!(d.localization, TrajectoryLocalization::End);
        assert_eq!(d.trend, TrajectoryTrend::Increasing);
    }

    #[test]
    fn two_repetition_patterns() {
        assert_eq!(
            dr(&[true], "repeat_index", &none(1), "none").drift,
            TrajectoryDrift::Persistent
        );
        assert_eq!(
            dr(&[true], "repeat_index", &none(1), "none").slew,
            TrajectorySlew::Stable
        );
        assert_eq!(
            dr(&[true, true], "repeat_index", &none(2), "none").drift,
            TrajectoryDrift::Persistent
        );
        let d = dr(&[false, true], "repeat_index", &none(2), "none");
        assert_eq!(d.drift, TrajectoryDrift::BoundaryLocalized);
        assert_eq!(d.slew, TrajectorySlew::Abrupt);
        assert_eq!(d.localization, TrajectoryLocalization::End);
    }

    #[test]
    fn empty_or_all_false_series_are_refused() {
        assert!(classify(&[], "repeat_index", &[], "none").is_err());
        assert!(classify(&[false, false], "repeat_index", &none(2), "none").is_err());
    }

    #[test]
    fn the_vocabulary_is_closed_and_distinct() {
        assert_eq!(TrajectoryDrift::ALL.len(), 5);
        assert_eq!(TrajectorySlew::ALL.len(), 5);
        assert_eq!(TrajectoryLocalization::ALL.len(), 5);
        assert_eq!(TrajectoryTrend::ALL.len(), 5);
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
        for (i, a) in TrajectoryTrend::ALL.iter().enumerate() {
            for (j, b) in TrajectoryTrend::ALL.iter().enumerate() {
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
