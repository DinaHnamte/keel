//! Onboarding: pure decision logic that runs before anything is installed.

pub mod preflight;

pub use preflight::{
    Finding, FirewallKind, HostFacts, InstallOptions, Severity, Support, firewall_rules,
    parse_facts, preflight, support,
};
