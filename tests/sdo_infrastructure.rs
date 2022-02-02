use chrono::{DateTime, Utc};
use stix4rust::core::sdos::infrastructure::Infrastructure;

/// A complete deserialization of the object grabbing values for each and every element.
#[test]
fn it_stix_object_complete_deserialization() {
    let text = r#"
    {
        "type": "infrastructure",
        "id": "infrastructure--38c47d93-d984-4fd9-b87b-d69d0841628d",
        "spec_version": "2.1",
        "created": "2016-05-07T11:22:30Z",
        "modified": "2016-05-07T11:22:30Z",
        "name": "Poison Ivy C2",
        "infrastructure_types": [
            "command-and-control"
        ]
    } 
    "#;
    let _object: Infrastructure = serde_json::from_str(text).unwrap();
}

/// A complete deserialization of a JSON object that has duplicate keys.
#[test]
#[should_panic]
fn it_stix_object_complete_deserialization_with_duplicate_key() {
    let text = r#"
    {
        "type": "infrastructure",
        "id": "infrastructure--38c47d93-d984-4fd9-b87b-d69d0841628d",
        "id": "infrastructure--38c47d93-d984-4fd9-b87b-d69d0841628d",
        "spec_version": "2.1",
        "created": "2016-05-07T11:22:30Z",
        "modified": "2016-05-07T11:22:30Z",
        "name": "Poison Ivy C2",
        "infrastructure_types": [
            "command-and-control"
        ]
    } 
    "#;
    let _object: Infrastructure = serde_json::from_str(text).unwrap();
}

/// A complete deserialization attempt that SHOULD fail because of a syntax error
#[test]
#[should_panic]
fn it_stix_object_syntax_error_complete_deserialization() {
    let text = r#"
    {
        "type": "infrastructure",
        "id": "infrastructure--38c47d93-d984-4fd9-b87b-d69d0841628d",
        "spec_version": "2.1,
        "created": "2016-05-07T11:22:30Z",
        "modified": "2016-05-07T11:22:30Z",
        "name": "Poison Ivy C2",
        "infrastructure_types": [
            "command-and-control"
        ]
    }      
    "#;
    let _object: Infrastructure = serde_json::from_str(text).unwrap();
}

/// Deserialization of a vulnerability with only the required fields.
#[test]
fn  it_stix_object_deserialization_with_required_fields_only() {
    let text = r#"
    {
        "type": "infrastructure",
        "id": "infrastructure--38c47d93-d984-4fd9-b87b-d69d0841628d",
        "spec_version": "2.1",
        "created": "2016-05-07T11:22:30Z",
        "modified": "2016-05-07T11:22:30Z",
        "name": "Poison Ivy C2"      
    }
    "#;
    let _object: Infrastructure = serde_json::from_str(text).unwrap();
}

/// Since there are some fields which are required, this test verifies that the deserialization method effectively detects that a panics.
#[test]
#[should_panic]
fn  it_stix_object_deserialization_with_missing_required_field() {
    let text = r#"
    {
        "type": "infrastructure",
        "id": "infrastructure--38c47d93-d984-4fd9-b87b-d69d0841628d",
        "spec_version": "2.1",
        "created": "2016-05-07T11:22:30Z",
        "modified": "2016-05-07T11:22:30Z",
    }
    "#;
    let object: Infrastructure = serde_json::from_str(text).unwrap();
    println!("{:#?}", object);
}

/// Serialization test of the object with certain values for the object.
/// Note that STIX 2.1 requires null values not appear in the object. This test verifies that optional values are not shown.
#[test]
fn  it_stix_object_serialization() {
    let object = Infrastructure {
        id: "infrastructure--38c47d93-d984-4fd9-b87b-d69d0841628d".to_string(),
        spec_version: "2.1".to_string(),
        created: DateTime::parse_from_rfc3339("2016-05-07T11:22:30Z").unwrap().with_timezone(&Utc),
        modified: DateTime::parse_from_rfc3339("2016-05-07T11:22:30Z").unwrap().with_timezone(&Utc),
        created_by_ref: None,
        revoked: None,
        labels: None,
        confidence: None,
        lang: None,
        external_references: None,
        object_marking_refs: None,
        granular_markings: None,
        name: "Poison Ivy C2".to_string(),
        description: None,
        infrastructure_types: Some(
            vec![
                "command-and-control".to_string(),
            ],
        ),
        aliases: None,
        kill_chain_phases: None,
        first_seen: None,
        last_seen: None,
    };
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}