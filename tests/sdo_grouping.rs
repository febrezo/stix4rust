use chrono::{DateTime, Utc};
use stix4rust::core::sdos::grouping::Grouping;

/// A complete deserialization of the object grabbing values for each and every element.
#[test]
fn it_stix_object_complete_deserialization() {
    let text = r#"
    {
        "type": "grouping",
        "spec_version": "2.1",
        "id": "grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
        "created_by_ref": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283",
        "created": "2015-12-21T19:59:11.000Z",
        "modified": "2015-12-21T19:59:11.000Z",
        "name": "The Black Vine Cyberespionage Group",
        "description": "A simple collection of Black Vine Cyberespionage Group attributed intel",
        "context": "suspicious-activity",
        "object_refs": [
        "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
            "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a",
            "file--0203b5c8-f8b6-4ddb-9ad0-527d727f968b"
        ]
    }
    "#;
    let _object: Grouping = serde_json::from_str(text).unwrap();
}

/// A complete deserialization of a JSON object that has duplicate keys.
#[test]
#[should_panic]
fn it_stix_object_complete_deserialization_with_duplicate_key() {
    let text = r#"
    {
        "type": "grouping",
        "spec_version": "2.1",
        "id": "grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
        "id": "grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
        "created_by_ref": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283",
        "created": "2015-12-21T19:59:11.000Z",
        "modified": "2015-12-21T19:59:11.000Z",
        "name": "The Black Vine Cyberespionage Group",
        "description": "A simple collection of Black Vine Cyberespionage Group attributed intel",
        "context": "suspicious-activity",
        "object_refs": [
        "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
            "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a",
            "file--0203b5c8-f8b6-4ddb-9ad0-527d727f968b"
        ]
    }
    "#;
    let _object: Grouping = serde_json::from_str(text).unwrap();
}

/// A complete deserialization attempt that SHOULD fail because of a syntax error
#[test]
#[should_panic]
fn it_stix_object_syntax_error_complete_deserialization() {
    let text = r#"
    {
        "type": "grouping",
        "spec_version": "2.1"
        "id": "grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
        "created_by_ref": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283",
        "created": "2015-12-21T19:59:11.000Z",
        "modified": "2015-12-21T19:59:11.000Z",
        "name": "The Black Vine Cyberespionage Group",
        "description": "A simple collection of Black Vine Cyberespionage Group attributed intel",
        "context": "suspicious-activity",
        "object_refs": [
        "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
            "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a",
            "file--0203b5c8-f8b6-4ddb-9ad0-527d727f968b"
        ]
    }  
    "#;
    let _object: Grouping = serde_json::from_str(text).unwrap();
}

/// Deserialization of a JSON object with only the required fields.
#[test]
fn  it_stix_object_deserialization_with_required_fields_only() {
    let text = r#"
    {
        "type": "grouping",
        "spec_version": "2.1",
        "id": "grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
        "created": "2015-12-21T19:59:11.000Z",
        "modified": "2015-12-21T19:59:11.000Z",
        "context": "suspicious-activity",
        "object_refs": [
        "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
            "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a",
            "file--0203b5c8-f8b6-4ddb-9ad0-527d727f968b"
        ]
    }
    "#;
    let _object: Grouping = serde_json::from_str(text).unwrap();
}

/// Since there are some fields which are required, this test verifies that the deserialization method effectively detects that a panics.
#[test]
#[should_panic]
fn  it_stix_object_deserialization_with_missing_required_field() {
    let text = r#"
    {
        "type": "grouping",
        "spec_version": "2.1",
        "id": "grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
        "created_by_ref": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283",
        "created": "2015-12-21T19:59:11.000Z",
        "modified": "2015-12-21T19:59:11.000Z",
        "name": "The Black Vine Cyberespionage Group",
        "description": "A simple collection of Black Vine Cyberespionage Group attributed intel",
        "object_refs": [
        "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
            "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a",
            "file--0203b5c8-f8b6-4ddb-9ad0-527d727f968b"
        ]
    }
    "#;
    let object: Grouping = serde_json::from_str(text).unwrap();
    println!("{:#?}", object);
}

/// Serialization test of the object with certain values for the object.
/// Note that STIX 2.1 requires null values not appear in the object. This test verifies that optional values are not shown.
#[test]
fn  it_stix_object_serialization() {
    let object = Grouping {
        id: "grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3".to_string(),
        spec_version: "2.1".to_string(),
        created: DateTime::parse_from_rfc3339("2015-12-21T19:59:11Z").unwrap().with_timezone(&Utc),
        modified: DateTime::parse_from_rfc3339("2015-12-21T19:59:11Z").unwrap().with_timezone(&Utc),
        created_by_ref: Some(
            "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283".to_string(),
        ),
        revoked: None,
        labels: None,
        confidence: None,
        lang: None,
        external_references: None,
        object_marking_refs: None,
        granular_markings: None,
        name: Some(
            "The Black Vine Cyberespionage Group".to_string(),
        ),
        description: Some(
            "A simple collection of Black Vine Cyberespionage Group attributed intel".to_string(),
        ),
        context: "suspicious-activity".to_string(),
        object_refs: vec![
            "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2".to_string(),
            "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c".to_string(),
            "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a".to_string(),
            "file--0203b5c8-f8b6-4ddb-9ad0-527d727f968b".to_string(),
        ],
    };
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}