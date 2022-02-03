use chrono::{DateTime, Utc};
use stix4rust::core::sdos::course_of_action::CourseOfAction;

/// A complete deserialization of the object grabbing values for each and every element.
#[test]
fn it_stix_object_complete_deserialization() {
    let text = r#"
    {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "name": "mitigation-poison-ivy-firewall",
        "description": "This action points to a recommended set of steps to respond to the Poison Ivy malware on a Cisco firewall device"
    }
    "#;
    let _object: CourseOfAction = serde_json::from_str(text).unwrap();
}

/// A complete deserialization of a JSON object that has duplicate keys.
#[test]
#[should_panic]
fn it_stix_object_complete_deserialization_with_duplicate_key() {
    let text = r#"
    {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "name": "mitigation-poison-ivy-firewall",
        "description": "This action points to a recommended set of steps to respond to the Poison Ivy malware on a Cisco firewall device"
    }
    "#;
    let _object: CourseOfAction = serde_json::from_str(text).unwrap();
}

/// A complete deserialization attempt that SHOULD fail because of a syntax error
#[test]
#[should_panic]
fn it_stix_object_syntax_error_complete_deserialization() {
    let text = r#"
    {
        "type": "course-of-action",
        "spec_version": "2.1"
        "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "name": "mitigation-poison-ivy-firewall",
        "description": "This action points to a recommended set of steps to respond to the Poison Ivy malware on a Cisco firewall device"
    }
    "#;
    let _object: CourseOfAction = serde_json::from_str(text).unwrap();
}

/// Deserialization of a JSON object with only the required fields.
#[test]
fn  it_stix_object_deserialization_with_required_fields_only() {
    let text = r#"
    {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "name": "mitigation-poison-ivy-firewall"
    }
    "#;
    let _object: CourseOfAction = serde_json::from_str(text).unwrap();
}

/// Deserialization of a JSON object with only required fields and extra fields which are not in the standard yet.
#[test]
fn  it_stix_object_deserialization_with_fields_which_are_not_in_the_standard_yet() {
    let text = r#"
    {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "name": "mitigation-poison-ivy-firewall",
        "description": "This action points to a recommended set of steps to respond to the Poison Ivy malware on a Cisco firewall device",
        "action_type": "cisco:ios",
        "action_reference":
        {
            "source_name": "internet",
            "url": "hxxps://www.stopthebad.com/poisonivyresponse.asa"
        }
    }
    "#;
    let _object: CourseOfAction = serde_json::from_str(text).unwrap();
}

/// Since there are some fields which are required, this test verifies that the deserialization method effectively detects that a panics.
#[test]
#[should_panic]
fn  it_stix_object_deserialization_with_missing_required_field() {
    let text = r#"
    {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z"
    }
    "#;
    let object: CourseOfAction = serde_json::from_str(text).unwrap();
    println!("{:#?}", object);
}

/// Serialization test of the object with certain values for the object.
/// Note that STIX 2.1 requires null values not appear in the object. This test verifies that optional values are not shown.
#[test]
fn  it_stix_object_serialization() {
    let object = CourseOfAction {
        id: "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f".to_string(),
        spec_version: "2.1".to_string(),
        created: DateTime::parse_from_rfc3339("2016-04-06T20:03:48Z").unwrap().with_timezone(&Utc),
        modified: DateTime::parse_from_rfc3339("2016-04-06T20:03:48Z").unwrap().with_timezone(&Utc),
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
        name: "mitigation-poison-ivy-firewall".to_string(),
        description: Some(
            "This action points to a recommended set of steps to respond to the Poison Ivy malware on a Cisco firewall device".to_string(),
        ),
    }
    ;
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}