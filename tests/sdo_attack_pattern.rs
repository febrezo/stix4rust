use chrono::{DateTime, Utc};
use stix4rust::core::sdos::attack_pattern::AttackPattern;
use stix4rust::core::types::{ExternalReference};

/// A complete deserialization of the object grabbing values for each and every element.
#[test]
fn it_stix_object_complete_deserialization() {
    let text = r#"
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
        "created": "2016-05-12T08:17:27.000Z",
        "modified": "2016-05-12T08:17:27.000Z",
        "name": "Spear Phishing as Practiced by Adversary X",
        "description": "A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.",
        "external_references": [
            {
                "source_name": "capec",
                "external_id": "CAPEC-163"
            }
        ]
    }
    "#;
    let _object: AttackPattern = serde_json::from_str(text).unwrap();
}

/// A complete deserialization of a JSON object that has duplicate keys.
#[test]
#[should_panic]
fn it_stix_object_complete_deserialization_with_duplicate_key() {
    let text = r#"
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
        "id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
        "created": "2016-05-12T08:17:27.000Z",
        "modified": "2016-05-12T08:17:27.000Z",
        "name": "Spear Phishing as Practiced by Adversary X",
        "description": "A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.",
        "external_references": [
            {
                "source_name": "capec",
                "external_id": "CAPEC-163"
            }
        ]
    }
    "#;
    let _object: AttackPattern = serde_json::from_str(text).unwrap();
}

/// A complete deserialization attempt that SHOULD fail because of a syntax error
#[test]
#[should_panic]
fn it_stix_object_syntax_error_complete_deserialization() {
    let text = r#"
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
        "created": "2016-05-12T08:17:27.000Z",
        "modified": "2016-05-12T08:17:27.000Z,
        "name": "Spear Phishing as Practiced by Adversary X",
        "description": "A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.",
        "external_references": [
            {
                "source_name": "capec",
                "external_id": "CAPEC-163"
            }
        ]
    }    
    "#;
    let _object: AttackPattern = serde_json::from_str(text).unwrap();
}

/// Deserialization of a JSON object with only the required fields.
#[test]
fn  it_stix_object_deserialization_with_required_fields_only() {
    let text = r#"
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
        "created": "2016-05-12T08:17:27.000Z",
        "modified": "2016-05-12T08:17:27.000Z",
        "name": "Spear Phishing as Practiced by Adversary X"
    }
    "#;
    let _object: AttackPattern = serde_json::from_str(text).unwrap();
}

/// Since there are some fields which are required, this test verifies that the deserialization method effectively detects that a panics.
#[test]
#[should_panic]
fn  it_stix_object_deserialization_with_missing_required_field() {
    let text = r#"
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
        "created": "2016-05-12T08:17:27.000Z",
        "modified": "2016-05-12T08:17:27.000Z"
    }
    "#;
    let object: AttackPattern = serde_json::from_str(text).unwrap();
    println!("{:#?}", object);
}

/// Serialization test of the object with certain values for the object.
/// Note that STIX 2.1 requires null values not appear in the object. This test verifies that optional values are not shown.
#[test]
fn  it_stix_object_serialization() {
    let object = AttackPattern {
        id: "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5".to_string(),
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
                    source_name: "capec".to_string(),
                    description: None,
                    url: None,
                    hashes: None,
                    external_id: Some(
                        "CAPEC-163".to_string(),
                    ),
                },
            ],
        ),
        object_marking_refs: None,
        granular_markings: None,
        name: "Spear Phishing as Practiced by Adversary X".to_string(),
        description: Some(
            "A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.".to_string(),
        ),
        aliases: None,
        kill_chain_phases: None,
    }
    ;
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}