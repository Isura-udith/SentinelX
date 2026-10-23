//! Security alert domain model, severity levels, alert status, and rule identifiers.
//!
//! # Defensive Security Philosophy
//! SentinelX is strictly a defensive analysis platform.
//!
//! **Important Operational Boundary**:
//! Alert generation must **never** automatically alter the host operating system, terminate
//! processes, block network traffic, or perform unilateral containment actions. In production
//! security operations, alerts represent reasoned hypotheses supported by observable telemetry
//! evidence for human analyst triage or orchestrated defensive workflows.

use crate::error::DomainError;
use crate::event::EventId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use uuid::Uuid;

/// Strongly typed, unique identifier for a generated [`SecurityAlert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AlertId(Uuid);

impl AlertId {
    /// Generates a new random (v4) `AlertId`.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Creates an `AlertId` from an existing UUID.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the underlying UUID reference.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for AlertId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AlertId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for AlertId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

/// Strongly typed identifier for a detection rule (e.g., `NET-001`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuleId(String);

impl RuleId {
    /// Creates a validated `RuleId`.
    ///
    /// # Errors
    /// Returns [`DomainError::EmptyRuleId`] if the ID is empty or whitespace.
    pub fn new(id: impl Into<String>) -> Result<Self, DomainError> {
        let s = id.into();
        if s.trim().is_empty() {
            return Err(DomainError::EmptyRuleId);
        }
        Ok(Self(s))
    }

    /// Returns the rule identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Severity classification for a security alert.
///
/// Each severity level conveys urgency and confidence based on defensive criteria:
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    /// Informational: Baseline observations, normal diagnostic signals, or contextual metrics.
    Informational,
    /// Low: Minor anomaly or low-risk variance from baseline; unlikely to indicate malicious intent.
    Low,
    /// Medium: Suspicious threshold breach exceeding typical baseline (e.g., moderate port reconnaissance).
    Medium,
    /// High: High-confidence anomalous activity with significant threat potential requiring expedited triage.
    High,
    /// Critical: Severe, widespread anomaly indicating high-velocity attack behavior or critical resource exposure.
    Critical,
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Informational => write!(f, "INFORMATIONAL"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Operational lifecycle triage status of a security alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    /// Newly emitted alert awaiting human analyst or automation review.
    Open,
    /// Alert acknowledged by an analyst and currently undergoing investigation.
    Acknowledged,
    /// Alert investigated and resolved (either closed as benign false positive or mitigated).
    Resolved,
}

impl fmt::Display for AlertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "OPEN"),
            Self::Acknowledged => write!(f, "ACKNOWLEDGED"),
            Self::Resolved => write!(f, "RESOLVED"),
        }
    }
}

/// A structured security alert emitted when a detection rule identifies anomalous patterns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityAlert {
    /// Unique identifier for this alert instance.
    pub id: AlertId,
    /// Identifier of the detection rule that triggered this alert.
    pub rule_id: RuleId,
    /// Classified severity level.
    pub severity: AlertSeverity,
    /// Short human-readable title summarizing the alert condition.
    pub title: String,
    /// In-depth explanation describing why the alert was generated and contextual caveats.
    pub explanation: String,
    /// Timestamp of the earliest supporting event observation.
    pub first_observed_at: DateTime<Utc>,
    /// Timestamp of the latest supporting event observation.
    pub last_observed_at: DateTime<Utc>,
    /// Total count of supporting telemetry observations evaluated.
    pub observation_count: usize,
    /// Relevant source IP address associated with the alert, when available.
    pub source_ip: Option<IpAddr>,
    /// List of representative event IDs serving as forensic evidence (bounded).
    pub evidence_event_ids: Vec<EventId>,
    /// Triage status of the alert.
    pub status: AlertStatus,
}

impl SecurityAlert {
    /// Validates the internal consistency and logical constraints of the alert.
    ///
    /// # Errors
    /// Returns [`DomainError`] if timestamps are inverted, strings are empty, or evidence is missing.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.first_observed_at > self.last_observed_at {
            return Err(DomainError::InvertedAlertTimeRange {
                first: self.first_observed_at,
                last: self.last_observed_at,
            });
        }

        if self.title.trim().is_empty() {
            return Err(DomainError::EmptyAlertTitle);
        }

        if self.explanation.trim().is_empty() {
            return Err(DomainError::EmptyAlertExplanation);
        }

        if self.evidence_event_ids.is_empty() {
            return Err(DomainError::EmptyAlertEvidence);
        }

        if self.observation_count < self.evidence_event_ids.len() {
            return Err(DomainError::ObservationCountMismatch {
                count: self.observation_count,
                evidence_count: self.evidence_event_ids.len(),
            });
        }

        Ok(())
    }
}

/// Builder for constructing and validating a [`SecurityAlert`].
#[derive(Debug, Clone)]
pub struct SecurityAlertBuilder {
    id: AlertId,
    rule_id: RuleId,
    severity: AlertSeverity,
    title: String,
    explanation: String,
    first_observed_at: DateTime<Utc>,
    last_observed_at: DateTime<Utc>,
    observation_count: usize,
    source_ip: Option<IpAddr>,
    evidence_event_ids: Vec<EventId>,
    status: AlertStatus,
}

impl SecurityAlertBuilder {
    /// Starts building a new [`SecurityAlert`] with required initial attributes.
    #[must_use]
    pub fn new(
        rule_id: RuleId,
        severity: AlertSeverity,
        title: impl Into<String>,
        explanation: impl Into<String>,
        first_observed_at: DateTime<Utc>,
        last_observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: AlertId::new(),
            rule_id,
            severity,
            title: title.into(),
            explanation: explanation.into(),
            first_observed_at,
            last_observed_at,
            observation_count: 0,
            source_ip: None,
            evidence_event_ids: Vec::new(),
            status: AlertStatus::Open,
        }
    }

    /// Sets an explicit alert ID.
    #[must_use]
    pub fn with_id(mut self, id: AlertId) -> Self {
        self.id = id;
        self
    }

    /// Sets the total observation count.
    #[must_use]
    pub fn with_observation_count(mut self, count: usize) -> Self {
        self.observation_count = count;
        self
    }

    /// Sets the relevant source IP address.
    #[must_use]
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Sets the optional source IP address.
    #[must_use]
    pub fn with_opt_source_ip(mut self, ip: Option<IpAddr>) -> Self {
        self.source_ip = ip;
        self
    }

    /// Adds supporting evidence event IDs.
    #[must_use]
    pub fn with_evidence_ids(mut self, ids: Vec<EventId>) -> Self {
        self.evidence_event_ids = ids;
        self
    }

    /// Sets the triage status.
    #[must_use]
    pub fn with_status(mut self, status: AlertStatus) -> Self {
        self.status = status;
        self
    }

    /// Validates and constructs the [`SecurityAlert`].
    ///
    /// # Errors
    /// Returns [`DomainError`] if validation fails.
    pub fn build(self) -> Result<SecurityAlert, DomainError> {
        let alert = SecurityAlert {
            id: self.id,
            rule_id: self.rule_id,
            severity: self.severity,
            title: self.title,
            explanation: self.explanation,
            first_observed_at: self.first_observed_at,
            last_observed_at: self.last_observed_at,
            observation_count: self.observation_count,
            source_ip: self.source_ip,
            evidence_event_ids: self.evidence_event_ids,
            status: self.status,
        };
        alert.validate()?;
        Ok(alert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_valid_alert_creation() {
        let now = Utc::now();
        let rule_id = RuleId::new("NET-001").expect("valid rule id");
        let ev_id = EventId::new();

        let alert = SecurityAlertBuilder::new(
            rule_id,
            AlertSeverity::Medium,
            "Potential Port Scan Activity Detected",
            "Observed 12 distinct destination ports from source.",
            now,
            now,
        )
        .with_source_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        .with_evidence_ids(vec![ev_id])
        .with_observation_count(1)
        .build()
        .expect("valid alert");

        assert_eq!(alert.severity, AlertSeverity::Medium);
        assert_eq!(alert.status, AlertStatus::Open);
        assert_eq!(alert.evidence_event_ids.len(), 1);
    }

    #[test]
    fn test_inverted_time_rejected() {
        let now = Utc::now();
        let earlier = now - chrono::Duration::seconds(10);
        let rule_id = RuleId::new("NET-001").expect("valid rule id");

        let result = SecurityAlertBuilder::new(
            rule_id,
            AlertSeverity::Medium,
            "Title",
            "Explanation",
            now,     // first observed is in the future relative to last observed
            earlier, // last observed
        )
        .with_evidence_ids(vec![EventId::new()])
        .with_observation_count(1)
        .build();

        assert!(matches!(
            result,
            Err(DomainError::InvertedAlertTimeRange { .. })
        ));
    }

    #[test]
    fn test_empty_evidence_rejected() {
        let now = Utc::now();
        let rule_id = RuleId::new("NET-001").expect("valid rule id");

        let result = SecurityAlertBuilder::new(
            rule_id,
            AlertSeverity::Low,
            "Title",
            "Explanation",
            now,
            now,
        )
        .with_evidence_ids(vec![])
        .build();

        assert_eq!(result.unwrap_err(), DomainError::EmptyAlertEvidence);
    }

    #[test]
    fn test_alert_serde_roundtrip() {
        let now = Utc::now();
        let rule_id = RuleId::new("NET-001").expect("valid rule id");
        let alert = SecurityAlertBuilder::new(
            rule_id,
            AlertSeverity::Critical,
            "Critical Port Sweep",
            "Source contacted 100+ ports",
            now,
            now,
        )
        .with_evidence_ids(vec![EventId::new()])
        .with_observation_count(100)
        .build()
        .expect("valid alert");

        let json = serde_json::to_string(&alert).expect("serialize alert");
        let deserialized: SecurityAlert = serde_json::from_str(&json).expect("deserialize alert");
        assert_eq!(alert, deserialized);
    }
}
