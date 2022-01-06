/// This module defines de Rust structures that represent the Stix Domain Objects, a. k. a. SDOs, as defined in [Section 4 of the Stix 2.1](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070669).
/// The set of STIX Domain Objects of this crate includes the following structures, being the name of the struct itself specified between brackets: 
///
/// - Attack Pattern (`AttackPattern`)
/// - Campaign (`Campaign`)
/// - Course of Action (`CourseOfAction`)
/// - Grouping (`Grouping`)
/// - Identity (`Identity`)
/// - Indicator (`Indicator`)
/// - Infrastructure (`Infrastructure`)
/// - Intrusion Set (`IntrusionSet`)
/// - Location (`Location`)
/// - Malware (`Malware`)
/// - Malware Analysis (`MalwareAnalysis`)
/// - Note (`Note`)
/// - Observed Data (`ObservedData`)
/// - Opinion (`Opinion`)
/// - Report (`Report`)
/// - Threat Actor (`ThreatActor`)
/// - Tool (`Tool`)
/// - Vulnerability (`Vulnerability`)
///
/// Each of these objects corresponds to a concept commonly used in Cyber Threat Intelligence investigations and implement the `STIXObject` trait so as to include the (de)serializing features associated to them.
/// Note that required parameters and optional parameters compatibility is majorly enforced so as to implement the requirements defined in the STIX standard itself.
pub mod report;
pub mod threat_actor;
pub mod tool;
pub mod vulnerability;
