use std::collections::HashMap;
use serde::{
    Serialize, 
    Deserialize
};
use validator::{
    Validate, 
    // ValidationError
};

#[derive(Serialize, Deserialize, Validate, Debug)]
pub struct ExternalReference {  
    pub source_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[validate(url)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

#[derive(Serialize, Deserialize, Validate, Debug)]
pub struct GranularMarking {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(min = 1))]
    pub lang: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marking_ref: Option<String>,
    #[validate(length(min = 1))]
    pub selectors: Vec<String>,
}

#[derive(Serialize, Deserialize, Validate, Debug)]
pub struct KillChainPhase {  
    pub kill_chain_name: String,
    pub phase_name: String,
}