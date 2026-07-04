//! Predicate types for the Verax Protocol.
//!
//! A predicate defines the semantic relationship between a statement's
//! subject and object. Each predicate is encoded as a single byte in the
//! statement's CBOR payload.
//!
//! # Predicate Codes
//!
//! | Code | Variant          | Description                                                    |
//! |------|------------------|----------------------------------------------------------------|
//! | 0    | `Attests`        | General claim of truth regarding the subject                   |
//! | 1    | `Authors`        | Issuer created the subject Artifact                            |
//! | 2    | `DerivedFrom`    | Subject Artifact was transformed from the Object Artifact      |
//! | 3    | `Supersedes`     | This Statement replaces the Object Statement                   |
//! | 4    | `Revokes`        | This Statement invalidates the Object Statement or Artifact    |
//! | 5    | `Endorses`       | Countersignature or multi-party approval                       |
//! | 6    | `Appends`        | Streaming chunk linkage (Subject is Chunk N, Object is Chunk N-1) |
//! | 7    | `CompliesWith`   | Subject Artifact satisfies the policy defined in Object Artifact |
//! | 8    | `Recovers`       | Guardian authorises replacement of a lost key                  |
//!
//! The constant [`CORE_PREDICATES`] provides a slice of all nine predicates
//! for iteration.

use crate::error::{Error, Result};

/// Semantic predicate for a Verax statement.
///
/// Each variant encodes the relationship between the statement's subject
/// and object. The numeric code is serialized as a single byte in the
/// statement payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Predicate {
    /// (0) General claim of truth regarding the subject.
    Attests = 0,
    /// (1) Issuer created the subject Artifact.
    Authors = 1,
    /// (2) Subject Artifact was transformed from the Object Artifact.
    DerivedFrom = 2,
    /// (3) This Statement replaces the Object Statement.
    Supersedes = 3,
    /// (4) This Statement invalidates the Object Statement or Artifact.
    Revokes = 4,
    /// (5) Countersignature or multi-party approval.
    Endorses = 5,
    /// (6) Streaming chunk linkage (Subject is Chunk N, Object is Chunk N-1).
    Appends = 6,
    /// (7) Subject Artifact satisfies the policy defined in Object Artifact.
    CompliesWith = 7,
    /// (8) Guardian authorises replacement of a lost key.
    Recovers = 8,
}

/// All nine core predicates, in code order (0..=8).
///
/// Useful for iterating over every predicate.
pub const CORE_PREDICATES: &[Predicate] = &[
    Predicate::Attests,
    Predicate::Authors,
    Predicate::DerivedFrom,
    Predicate::Supersedes,
    Predicate::Revokes,
    Predicate::Endorses,
    Predicate::Appends,
    Predicate::CompliesWith,
    Predicate::Recovers,
];

impl Predicate {
    /// Convert a `u8` to a [`Predicate`].
    ///
    /// Returns `Error::InvalidField("predicate")` if the value is not in
    /// the range 0..=8.
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Predicate::Attests),
            1 => Ok(Predicate::Authors),
            2 => Ok(Predicate::DerivedFrom),
            3 => Ok(Predicate::Supersedes),
            4 => Ok(Predicate::Revokes),
            5 => Ok(Predicate::Endorses),
            6 => Ok(Predicate::Appends),
            7 => Ok(Predicate::CompliesWith),
            8 => Ok(Predicate::Recovers),
            _ => Err(Error::InvalidField("predicate")),
        }
    }

    /// Return the numeric code of this predicate (0..=8).
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Return the uppercase constant-style name of this predicate
    /// (e.g. `"ATTESTS"`, `"DERIVED_FROM"`).
    pub fn name(&self) -> &'static str {
        match self {
            Predicate::Attests => "ATTESTS",
            Predicate::Authors => "AUTHORS",
            Predicate::DerivedFrom => "DERIVED_FROM",
            Predicate::Supersedes => "SUPERSEDES",
            Predicate::Revokes => "REVOKES",
            Predicate::Endorses => "ENDORSES",
            Predicate::Appends => "APPENDS",
            Predicate::CompliesWith => "COMPLIES_WITH",
            Predicate::Recovers => "RECOVERS",
        }
    }

    /// Return a human-readable description of what this predicate means.
    pub fn description(&self) -> &'static str {
        match self {
            Predicate::Attests => "General claim of truth regarding the subject",
            Predicate::Authors => "Issuer created the subject Artifact",
            Predicate::DerivedFrom => "Subject Artifact was transformed from the Object Artifact",
            Predicate::Supersedes => "This Statement replaces the Object Statement",
            Predicate::Revokes => "This Statement invalidates the Object Statement or Artifact",
            Predicate::Endorses => "Countersignature or multi-party approval",
            Predicate::Appends => {
                "Streaming chunk linkage (Subject is Chunk N, Object is Chunk N-1)"
            }
            Predicate::CompliesWith => {
                "Subject Artifact satisfies the policy defined in Object Artifact"
            }
            Predicate::Recovers => "Guardian authorises replacement of a lost key",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_predicates_round_trip() {
        for p in CORE_PREDICATES {
            let v = p.to_u8();
            let back = Predicate::from_u8(v).unwrap();
            assert_eq!(*p, back);
        }
    }

    #[test]
    fn test_predicate_names() {
        assert_eq!(Predicate::Attests.name(), "ATTESTS");
        assert_eq!(Predicate::Revokes.name(), "REVOKES");
    }

    #[test]
    fn test_invalid_predicate() {
        assert!(Predicate::from_u8(255).is_err());
    }
}
