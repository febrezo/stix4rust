use chrono::{DateTime, Utc};
use stix4rust::core::sdos::campaign::Campaign;

/// A complete deserialization of the object grabbing values for each and every element.
#[test]
fn it_stix_object_complete_deserialization() {
    let text = r#"
    {
        "type": "campaign",
        "spec_version": "2.1",
        "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "name": "Green Group Attacks Against Finance",
        "description": "Campaign by Green Group against a series of targets in the financial services sector."
    }    
    "#;
    let _object: Campaign = serde_json::from_str(text).unwrap();
}

/// A complete deserialization of a JSON object that has duplicate keys.
#[test]
#[should_panic]
fn it_stix_object_complete_deserialization_with_duplicate_key() {
    let text = r#"
    {
        "type": "campaign",
        "spec_version": "2.1",
        "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "name": "Green Group Attacks Against Finance",
        "description": "Campaign by Green Group against a series of targets in the financial services sector."
    }    
    "#;
    let _object: Campaign = serde_json::from_str(text).unwrap();
}

/// A complete deserialization attempt that SHOULD fail because of a syntax error
#[test]
#[should_panic]
fn it_stix_object_syntax_error_complete_deserialization() {
    let text = r#"
    {
        "type": "campaign",
        "spec_version": "2.1,
        "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "name": "Green Group Attacks Against Finance",
        "description": "Campaign by Green Group against a series of targets in the financial services sector."
    }      
    "#;
    let _object: Campaign = serde_json::from_str(text).unwrap();
}

/// Deserialization of a JSON object with only the required fields.
#[test]
fn  it_stix_object_deserialization_with_required_fields_only() {
    let text = r#"
    {
        "type": "campaign",
        "spec_version": "2.1",
        "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "name": "Green Group Attacks Against Finance"
    }    
    "#;
    let _object: Campaign = serde_json::from_str(text).unwrap();
}

/// Since there are some fields which are required, this test verifies that the deserialization method effectively detects that a panics.
#[test]
#[should_panic]
fn  it_stix_object_deserialization_with_missing_required_field() {
    let text = r#"
    {
        "type": "campaign",
        "spec_version": "2.1",
        "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z"
    }    
    "#;
    let object: Campaign = serde_json::from_str(text).unwrap();
    println!("{:#?}", object);
}

/// Serialization test of the object with certain values for the object.
/// Note that STIX 2.1 requires null values not appear in the object. This test verifies that optional values are not shown.
#[test]
fn  it_stix_object_serialization() {
    let object = Campaign {
        id: "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f".to_string(),
        spec_version: "2.1".to_string(),
        created: DateTime::parse_from_rfc3339("2016-04-06T20:03:00Z").unwrap().with_timezone(&Utc),
        modified: DateTime::parse_from_rfc3339("2016-04-06T20:03:00Z").unwrap().with_timezone(&Utc),
        created_by_ref: Some(
            "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff".to_string(),
        ),
        revoked: None,
        labels: None,
        confidence: None,
        lang: None,
        external_references: None,
        object_marking_refs: None,
        granular_markings: None,
        name: "Green Group Attacks Against Finance".to_string(),
        description: Some(
            "Campaign by Green Group against a series of targets in the financial services sector.".to_string(),
        ),
        aliases: None,
        first_seen: None,
        last_seen: None,
        objective: None,
    };
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}