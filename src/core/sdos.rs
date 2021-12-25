use serde::{
    Serialize, 
    Deserialize
};
use super::types::{
    ExternalReference,
    GranularMarking
};
use super::STIXObject;

/// Defines the enum object that represents the Stix Domain Objects as defined in [Section 4 of the Stix 2.1](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070669)
/// As defined by the standard itself, the set of STIX Domain Objects, a. k. a. SDOs, includes the following SDO with the name of the class as defined in thsi library included between brackets: 
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
/// Each of these objects corresponds to a concept commonly used in Cyber Threat Intelligence investigations. Note that all the optional and required parameters are included so as to fulfill the STIX standard requirements.
///
/// # Example
/// 
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SDO {
    ThreatActor {
        // Required common properties
        id: String,
        spec_version: String,
        created: String,
        modified: String,
        // Optional common properties
        #[serde(skip_serializing_if = "Option::is_none")]
        created_by_ref: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        revoked: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        labels: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        confidence: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        lang: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        external_references: Option<Vec<ExternalReference>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        object_marking_refs: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        granular_markings: Option<Vec<GranularMarking>>,
        // Specific properties
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        threat_actor_types: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        aliases: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        first_seen: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_seen: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        roles: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        goals: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sophistication: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        resource_level: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        primary_motivation: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        secondary_motivations: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        personal_motivations: Option<Vec<String>>
    },
    Tool {
        // Required common properties
        id: String,
        spec_version: String,
        created: String,
        modified: String,
        // Optional common properties
        #[serde(skip_serializing_if = "Option::is_none")]
        created_by_ref: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        revoked: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        labels: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        confidence: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        lang: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        external_references: Option<Vec<ExternalReference>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        object_marking_refs: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        granular_markings: Option<Vec<GranularMarking>>,
        // Specific properties
        name: String,
        description: String,
        tool_types: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        aliases: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        kill_chain_phases: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tool_version: Option<String>
    },
    Vulnerability {
        // Required common properties
        id: String,
        spec_version: String,
        created: String,
        modified: String,
        // Optional common properties
        #[serde(skip_serializing_if = "Option::is_none")]
        created_by_ref: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        revoked: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        labels: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        confidence: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        lang: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        external_references: Option<Vec<ExternalReference>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        object_marking_refs: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        granular_markings: Option<Vec<GranularMarking>>,
        // Specific properties
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    }
}


impl STIXObject for crate::core::sdos::SDO {

}