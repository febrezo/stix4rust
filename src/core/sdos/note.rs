use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use validator::Validate;
use crate::core::STIXObject;
use crate::core::types::{ExternalReference,GranularMarking};

#[derive(Serialize, Deserialize, Validate, Debug)]
pub struct Note {
    // Required common properties
    pub id: String,
    pub spec_version: String,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    // Optional common properties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_references: Option<Vec<ExternalReference>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_marking_refs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granular_markings: Option<Vec<GranularMarking>>,
    // Specific properties
    #[serde(rename(serialize = "abstract", deserialize = "abstract"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_refs: Option<Vec<String>>
}

#[typetag::serde(name = "note")]
impl STIXObject for Note {}