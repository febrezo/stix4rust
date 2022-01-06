use chrono::{DateTime, Utc};
use stix4rust::core::sdos::opinion::{
    Opinion,
    OpinionEnum
};

/// A complete deserialization of the object grabbing values for each and every element.
#[test]
fn it_stix_object_complete_deserialization() {
    let text = r#"
    {
        "type": "opinion",
        "id": "opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7",
        "spec_version": "2.1",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "revoked": false,
        "labels": ["hack"],
        "confidence": 100,
        "lang": "en",
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
        "explanation": "This doesn't seem like it is feasible. We've seen how PandaCat has attacked Spanish infrastructure over the last 3 years, so this change in targeting seems too great to be viable. The methods used are more commonly associated with the FlameDragonCrew.",
        "opinion": "strongly-disagree",
        "object_refs": [
            "relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471"
        ]
    }
    "#;
    let _object: Opinion = serde_json::from_str(text).unwrap();
}

/// A complete deserialization of a JSON object that has duplicate keys.
#[test]
#[should_panic]
fn it_stix_object_complete_deserialization_with_duplicate_key() {
    let text = r#"
    {
        "type": "opinion",
        "id": "opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7",
        "id": "opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7",
        "spec_version": "2.1",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "revoked": false,
        "labels": ["hack"],
        "confidence": 100,
        "lang": "en",
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
        "explanation": "This doesn't seem like it is feasible. We've seen how PandaCat has attacked Spanish infrastructure over the last 3 years, so this change in targeting seems too great to be viable. The methods used are more commonly associated with the FlameDragonCrew.",
        "opinion": "strongly-disagree",
        "object_refs": [
            "relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471"
        ]
    }
    "#;
    let _object: Opinion = serde_json::from_str(text).unwrap();
}

/// A complete deserialization attempt that SHOULD fail because of a syntax error
#[test]
#[should_panic]
fn it_stix_object_syntax_error_complete_deserialization() {
    let text = r#"
    {
        "type": "opinion",
        "id": "opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7",
        "spec_version": "2.1",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "revoked": false,
        "labels": ["syntax-error-here",
        "confidence": 100,
        "lang": "en",
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
        "explanation": "This doesn't seem like it is feasible. We've seen how PandaCat has attacked Spanish infrastructure over the last 3 years, so this change in targeting seems too great to be viable. The methods used are more commonly associated with the FlameDragonCrew.",
        "opinion": "strongly-disagree",
        "object_refs": [
            "relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471"
        ]
    }
    "#;
    let _object: Opinion = serde_json::from_str(text).unwrap();
}

/// A complete deserialization attempt that SHOULD fail because the opinion is not correct.
#[test]
#[should_panic]
fn it_stix_object_syntax_error_wrong_opinion() {
    let text = r#"
    {
        "type": "opinion",
        "id": "opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7",
        "spec_version": "2.1",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "revoked": false,
        "labels": ["syntax-error-here",
        "confidence": 100,
        "lang": "en",
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
        "explanation": "This doesn't seem like it is feasible. We've seen how PandaCat has attacked Spanish infrastructure over the last 3 years, so this change in targeting seems too great to be viable. The methods used are more commonly associated with the FlameDragonCrew.",
        "opinion": "invented",
        "object_refs": [
            "relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471"
        ]
    }
    "#;
    let _object: Opinion = serde_json::from_str(text).unwrap();
}

/// Deserialization of a vulnerability with only the required fields.
#[test]
fn  it_stix_object_deserialization_with_required_fields_only() {
    let text = r#"
    {
        "type": "opinion",
        "id": "opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7",
        "spec_version": "2.1",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "opinion": "strongly-disagree",
        "object_refs": [
            "relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471"
        ]
    }
    "#;
    let _object: Opinion = serde_json::from_str(text).unwrap();
}

/// Since there are some fields which are required, this test verifies that the deserialization method effectively detects that a panics.
#[test]
#[should_panic]
fn  it_stix_object_deserialization_with_missing_required_field() {
    let text = r#"
    {
        "type": "opinion",
        "id": "opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7",
        "spec_version": "2.1",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "object_refs": [
            "relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471"
        ]
    }
    "#;
    let object: Opinion = serde_json::from_str(text).unwrap();
    println!("{:#?}", object);
}

/// Serialization test of the object with certain values for the object.
/// Note that STIX 2.1 requires null values not appear in the object. This test verifies that optional values are not shown.
#[test]
fn  it_stix_object_serialization() {
    let object = Opinion {
        id: "opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7".to_string(),
        spec_version: "2.1".to_string(),
        created: DateTime::parse_from_rfc3339("2016-05-12T08:17:27Z").unwrap().with_timezone(&Utc),
        modified: DateTime::parse_from_rfc3339("2016-05-12T08:17:27Z").unwrap().with_timezone(&Utc),
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
        explanation: Some(
            "This doesn't seem like it is feasible. We've seen how PandaCat has attacked Spanish infrastructure over the last 3 years, so this change in targeting seems too great to be viable. The methods used are more commonly associated with the FlameDragonCrew.".to_string(),
        ),
        opinion: OpinionEnum::StronglyDisagree,
        authors: None,
        object_refs: Some(
            vec![
                "relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471".to_string(),
            ],
        ),
    };
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}