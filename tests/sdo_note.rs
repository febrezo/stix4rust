use chrono::{DateTime, Utc};
use stix4rust::core::sdos::note::Note;
use stix4rust::core::types::ExternalReference;

/// A complete deserialization of the object grabbing values for each and every element.
#[test]
fn it_stix_object_complete_deserialization() {
    let text = r#"
    {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        "created": "2016-05-12T08:17:27.000Z",
        "modified": "2016-05-12T08:17:27.000Z",
        "external_references": [
            {
                "source_name": "job-tracker",
                "id": "job-id-1234"
            }
        ],
        "abstract": "Tracking Team Note#1",
        "content": "This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc",
        "authors": ["John Doe"],
        "object_refs": ["campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"]
    }
    "#;
    let _object: Note = serde_json::from_str(text).unwrap();
}

/// A complete deserialization of a JSON object that has duplicate keys.
#[test]
#[should_panic]
fn it_stix_object_complete_deserialization_with_duplicate_key() {
    let text = r#"
    {
        "type": "note",
        "spec_version": "2.1",
        "spec_version": "2.1",
        "id": "note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        "created": "2016-05-12T08:17:27.000Z",
        "modified": "2016-05-12T08:17:27.000Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "revoked": false,
        "labels": ["test],
        "confidence": 100,
        "lang": "en",
        "external_references": [
            {
                "source_name": "job-tracker",
                "id": "job-id-1234"
            }
        ],
        "abstract": "Tracking Team Note#1",
        "content": "This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc",
        "authors": ["John Doe"],
        "object_refs": ["campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"]
    }
    "#;
    let _object: Note = serde_json::from_str(text).unwrap();
}

/// A complete deserialization attempt that SHOULD fail because of a syntax error
#[test]
#[should_panic]
fn it_stix_object_syntax_error_complete_deserialization() {
    let text = r#"
    {
        "type": "note",
        "spec_version": "2.1",
        "spec_version": "2.1",
        "id": "note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        "created": "2016-05-12T08:17:27.000Z",
        "modified": "2016-05-12T08:17:27.000Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "revoked": false,
        "labels": ["test],
        "confidence": 100,
        "lang": "en",
        "external_references": [
            {
                "source_name": "job-tracker",
                "id": "job-id-1234"
            }
        ],
        "abstract": "Tracking Team Note#1",
        "content": "This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc",
        "authors": ["John Doe"],
        "object_refs": ["campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"]
    }
    "#;
    let _object: Note = serde_json::from_str(text).unwrap();
}

/// Deserialization of a vulnerability with only the required fields.
#[test]
fn  it_stix_object_deserialization_with_required_fields_only() {
    let text = r#"
    {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        "created": "2016-05-12T08:17:27.000Z",
        "modified": "2016-05-12T08:17:27.000Z",
        "content": "This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc"
    }
    "#;
    let _object: Note = serde_json::from_str(text).unwrap();
}

/// Since there are some fields which are required, this test verifies that the deserialization method effectively detects that a panics.
#[test]
#[should_panic]
fn  it_stix_object_deserialization_with_missing_required_field() {
    let text = r#"
    {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        "created": "2016-05-12T08:17:27.000Z",
        "content": "This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc"
    }
    "#;
    let object: Note = serde_json::from_str(text).unwrap();
    println!("{:#?}", object);
}

/// Serialization test of the object with certain values for the object.
/// Note that STIX 2.1 requires null values not appear in the object. This test verifies that optional values are not shown.
#[test]
fn  it_stix_object_serialization() {
    let object = Note {
        id: "note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061".to_string(),
        spec_version: "2.1".to_string(),
        created: DateTime::parse_from_rfc3339("2016-05-12T08:17:27Z").unwrap().with_timezone(&Utc),
        modified: DateTime::parse_from_rfc3339("2016-05-12T08:17:27Z").unwrap().with_timezone(&Utc),
        created_by_ref: None,
        revoked: None,
        labels: None,
        confidence: None,
        lang: None,
        external_references: Some(
            vec![
                ExternalReference {
                    source_name: "job-tracker".to_string(),
                    description: None,
                    url: None,
                    hashes: None,
                    external_id: None,
                },
            ],
        ),
        object_marking_refs: None,
        granular_markings: None,
        summary: Some(
            "Tracking Team Note#1".to_string(),
        ),
        content: "This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc".to_string(),
        authors: Some(
            vec![
                "John Doe".to_string(),
            ],
        ),
        object_refs: Some(
            vec![
                "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f".to_string(),
            ],
        )
    };
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}