use chrono::{DateTime, Utc};
use stix4rust::core::sdos::identity::Identity;
use stix4rust::core::types::{
    ExternalReference,
    GranularMarking
};

/// A complete deserialization of the object grabbing values for each and every element.
#[test]
fn it_tool_complete_deserialization() {
    let text = r#"
    {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "name": "John Smith",
        "identity_class": "individual"
    }
    "#;
    let _object: Identity = serde_json::from_str(text).unwrap();
}

/// A complete deserialization attempt that SHOULD fail because of a syntax error
#[test]
#[should_panic]
fn it_tool_syntax_error_complete_deserialization() {
    let text = r#"
    {
        "type": "identity",
        "spec_version": "2.1"
        "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "name": "John Smith",
        "identity_class": "individual"
    }
    "#;
    let _object: Identity = serde_json::from_str(text).unwrap();
}


/// A complete deserialization of a JSON object that has duplicate keys.
#[test]
#[should_panic]
fn it_tool_complete_deserialization_with_duplicate_keys() {
    let text = r#"
    {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
        "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "name": "John Smith",
        "identity_class": "individual"
    }
    "#;
    let _object: Identity = serde_json::from_str(text).unwrap();
}


/// Deserialization of a vulnerability with only the required fields.
#[test]
fn it_tool_deserialization_with_required_fields_only() {
    let text = r#"
    {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "name": "John Smith"
    }
    "#;
    let _object: Identity = serde_json::from_str(text).unwrap();
}

/// Since there are some fields which are required, this test verifies that the deserialization method effectively detects that a panics.
#[test]
#[should_panic]
fn it_tool_deserialization_with_missing_required_field() {
    let text = r#"
    {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "identity_class": "individual"
    }
    "#;
    let object: Identity = serde_json::from_str(text).unwrap();
    println!("{:#?}", object);
}

/// Serialization test of the object with certain values for the object.
#[test]
fn it_tool_complete_serialization() {
    let object = Identity {
        id: "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e".to_string(),
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
        name: "John Smith".to_string(),
        description: None,
        roles: None,
        identity_class: Some(
            "individual".to_string(),
        ),
        sectors: None,
        contact_information: None,
    };
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}
