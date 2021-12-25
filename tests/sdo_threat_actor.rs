use stix4rust::core::sdos::SDO;
use stix4rust::core::types::{
    ExternalReference,
    GranularMarking
};

/// A complete deserialization of the object grabbing values for each and every element.
#[test]
fn it_threat_actor_complete_deserialization() {
    let text = r#"
    {
        "type": "threat-actor", 
        "spec_version": "2.1",
        "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "revoked": false,
        "labels": ["hack"],
        "confidence": 100,
        "external_references": [
            {
                "source_name": "NASA",
                "external_id": "NASA-2021"
            }
        ],
        "granular_markings": [
            {
                "lang": "es",
                "selectors": ["sel1", "sel2"]
            }
        ],
        "object_marking_refs": [],
        "threat_actor_types": [ "crime-syndicate"],
        "name": "Evil Org",
        "description": "The Evil Org threat actor group",
        "aliases": ["Syndicate 1", "Evil Syndicate 99"],
        "roles": ["director"],
        "goals": ["Steal bank money", "Steal credit cards"],
        "sophistication": "advanced",
        "resource_level": "team",
        "primary_motivation": "organizational-gain"
    }
    "#;
    let _object: SDO = serde_json::from_str(text).unwrap();
}

/// A complete deserialization of a JSON object that has duplicate keys.
#[test]
#[should_panic]
fn it_threat_actor_complete_deserialization_with_duplicate_key() {
    let text = r#"
    {
        "type": "threat-actor", 
        "spec_version": "2.1",
        "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "revoked": false,
        "labels": ["hack"],
        "confidence": 100,
        "external_references": [
            {
                "source_name": "NASA",
                "external_id": "NASA-2021"
            }
        ],
        "granular_markings": [
            {
                "lang": "es",
                "selectors": ["sel1", "sel2"]
            }
        ],
        "object_marking_refs": [],
        "threat_actor_types": [ "crime-syndicate"],
        "name": "Evil Org",
        "description": "The Evil Org threat actor group",
        "aliases": ["Syndicate 1", "Evil Syndicate 99"],
        "roles": ["director"],
        "goals": ["Steal bank money", "Steal credit cards"],
        "sophistication": "advanced",
        "resource_level": "team",
        "primary_motivation": "organizational-gain",
    }"#;
    let _object: SDO = serde_json::from_str(text).unwrap();
}

/// A complete deserialization attempt that SHOULD fail because of a syntax error
#[test]
#[should_panic]
fn it_threat_actor_syntax_error_complete_deserialization() {
    let text = r#"
    {
        "type": "threat-actor", 
        "spec_version": "2.1",
        "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "revoked": false,
        "labels": ["syntax-error-here",
        "confidence": 100,
        "external_references": [
            {
                "source_name": "NASA",
                "external_id": "NASA-2021"
            }
        ],
        "granular_markings": [
            {
                "lang": "es",
                "selectors": ["sel1", "sel2"]
            }
        ],
        "object_marking_refs": [],
        "threat_actor_types": [ "crime-syndicate"],
        "name": "Evil Org",
        "description": "The Evil Org threat actor group",
        "aliases": ["Syndicate 1", "Evil Syndicate 99"],
        "roles": ["director"],
        "goals": ["Steal bank money", "Steal credit cards"],
        "sophistication": "advanced",
        "resource_level": "team",
        "primary_motivation": "organizational-gain",
    }"#;
    let _object: SDO = serde_json::from_str(text).unwrap();
}


/// Deserialization of a vulnerability with only the required fields.
#[test]
fn  it_threat_actor_deserialization_with_required_fields_only() {
    let text = r#"
    {
        "type": "threat-actor", 
        "spec_version": "2.1",
        "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "threat_actor_types": [ "crime-syndicate"],
        "name": "Evil Org"
    }"#;
    let _object: SDO = serde_json::from_str(text).unwrap();
}

/// Since there are some fields which are required, this test verifies that the deserialization method effectively detects that a panics.
#[test]
#[should_panic]
fn  it_threat_actor_deserialization_with_missing_required_field() {
    let text = r#"
    {
        "type": "threat-actor", 
        "spec_version": "2.1",
        "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "threat_actor_types": [ "crime-syndicate"],
    }"#;
    let object: SDO = serde_json::from_str(text).unwrap();
    println!("{:#?}", object);
}

/// Serialization test of the object with certain values for the object.
#[test]
fn  it_threat_actor_complete_serialization() {
    let object: SDO = SDO::Vulnerability {
        id: "vulnerability--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061".to_string(),
        spec_version: "2.1".to_string(),
        created: "2016-05-12T08:17:27.000Z".to_string(),
        modified: "2016-05-12T08:17:27.000Z".to_string(),
        created_by_ref: Some(
            "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff".to_string(),
        ),
        revoked:  Some(false),
        labels: Some(vec!["sample".to_string()]),
        confidence: Some(100),
        lang: Some("en".to_string()),
        external_references: Some(
            vec![
                ExternalReference {
                    source_name: "cve".to_string(),
                    description: None,
                    url: None,
                    hashes: None,
                    external_id: Some(
                        "CVE-2016-1234".to_string(),
                    ),
                },
            ],
        ),
        object_marking_refs: None,
        granular_markings: Some(
            vec![
                GranularMarking {
                    lang: Some("en".to_string()),
                    marking_ref: None,
                    selectors: vec!["sel1".to_string(), "sel2".to_string()],
                }
                
            ]
        ),
        name: "CVE-2016-1234".to_string(),
        description: Some(
            "A dangerous CVE".to_string(),
        ),
    };   
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}

/// Stix 2.1 requires null values not appear in the object. This test verifies that optional values are not shown.
#[test]
fn  it_threat_actor_serialization_without_optional_attributes() {
    let object: SDO = SDO::Vulnerability {
        id: "vulnerability--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061".to_string(),
        spec_version: "2.1".to_string(),
        created: "2016-05-12T08:17:27.000Z".to_string(),
        modified: "2016-05-12T08:17:27.000Z".to_string(),
        created_by_ref: Some(
            "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff".to_string(),
        ),
        revoked: None,
        labels: None,
        confidence: None,
        lang: None,
        external_references: Some(
            vec![
                ExternalReference {
                    source_name: "cve".to_string(),
                    description: None,
                    url: None,
                    hashes: None,
                    external_id: Some(
                        "CVE-2016-1234".to_string(),
                    ),
                },
            ],
        ),
        object_marking_refs: None,
        granular_markings: None,
        name: "CVE-2016-1234".to_string(),
        description: Some(
            "A dangerous CVE".to_string(),
        ),
    };    
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}
