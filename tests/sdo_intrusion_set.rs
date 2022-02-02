use chrono::{DateTime, Utc};
use stix4rust::core::sdos::intrusion_set::IntrusionSet;

/// A complete deserialization of the object grabbing values for each and every element.
#[test]
fn it_stix_object_complete_deserialization() {
    let text = r#"
    {
        "type": "intrusion-set",
        "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
        "spec_version": "2.1",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
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
        "name": "Bobcat Breakin",
        "description": "Incidents usually feature a shared TTP of a bobcat being released within the building containing network access, scaring users to leave their computers without locking them first. Still determining where the threat actors are getting the bobcats.",
        "aliases": [
          "Zookeeper"
        ],
        "first_seen": "2016-04-06T20:03:48Z",
        "last_seen": "2016-04-06T20:03:48Z",
        "goals": [
          "acquisition-theft",
          "harassment",
          "damage"
        ],
        "primary_motivation": "hacking",
        "secondary_motivations": []
    }
    "#;
    let _object: IntrusionSet = serde_json::from_str(text).unwrap();
}

/// A complete deserialization of a JSON object that has duplicate keys.
#[test]
#[should_panic]
fn it_stix_object_complete_deserialization_with_duplicate_key() {
    let text = r#"
    {
        "type": "intrusion-set",
        "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
        "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
        "spec_version": "2.1",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
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
        "name": "Bobcat Breakin",
        "description": "Incidents usually feature a shared TTP of a bobcat being released within the building containing network access, scaring users to leave their computers without locking them first. Still determining where the threat actors are getting the bobcats.",
        "aliases": [
          "Zookeeper"
        ],
        "first_seen": "2016-04-06T20:03:48Z",
        "last_seen": "2016-04-06T20:03:48Z",
        "goals": [
          "acquisition-theft",
          "harassment",
          "damage"
        ],
        "primary_motivation": "hacking",
        "secondary_motivations": []
    }
    "#;
    let _object: IntrusionSet = serde_json::from_str(text).unwrap();
}

/// A complete deserialization attempt that SHOULD fail because of a syntax error
#[test]
#[should_panic]
fn it_stix_object_syntax_error_complete_deserialization() {
    let text = r#"
    {
        "type": "intrusion-set",
        "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
        "spec_version": "2.1",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "revoked": false,
        "labels": ["hack",
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
        "name": "Bobcat Breakin",
        "description": "Incidents usually feature a shared TTP of a bobcat being released within the building containing network access, scaring users to leave their computers without locking them first. Still determining where the threat actors are getting the bobcats.",
        "aliases": [
          "Zookeeper"
        ],
        "first_seen": "2016-04-06T20:03:48Z",
        "last_seen": "2016-04-06T20:03:48Z",
        "goals": [
          "acquisition-theft",
          "harassment",
          "damage"
        ],
        "primary_motivation": "hacking",
        "secondary_motivations": []
    }
    "#;
    let _object: IntrusionSet = serde_json::from_str(text).unwrap();
}

/// Deserialization of a vulnerability with only the required fields.
#[test]
fn  it_stix_object_deserialization_with_required_fields_only() {
    let text = r#"
    {
        "type": "intrusion-set",
        "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
        "spec_version": "2.1",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "name": "Bobcat Breakin"
    }
    "#;
    let _object: IntrusionSet = serde_json::from_str(text).unwrap();
}

/// Since there are some fields which are required, this test verifies that the deserialization method effectively detects that a panics.
#[test]
#[should_panic]
fn  it_stix_object_deserialization_with_missing_required_field() {
    let text = r#"
    {
        "type": "intrusion-set",
        "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
        "spec_version": "2.1",
        "created": "2016-04-06T20:03:48Z",
        "name": "Bobcat Breakin"
    }
    "#;
    let object: IntrusionSet = serde_json::from_str(text).unwrap();
    println!("{:#?}", object);
}

/// Serialization test of the object with certain values for the object.
/// Note that STIX 2.1 requires null values not appear in the object. This test verifies that optional values are not shown.
#[test]
fn  it_stix_object_serialization() {
    let object = IntrusionSet {
        id: "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29".to_string(),
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
        name: "Bobcat Breakin".to_string(),
        description: Some(
            "Incidents usually feature a shared TTP of a bobcat being released within the building containing network access, scaring users to leave their computers without locking them first. Still determining where the threat actors are getting the bobcats.".to_string(),
        ),
        aliases: Some(
            vec![
                "Zookeeper".to_string(),
            ],
        ),
        first_seen: None,
        last_seen: None,
        goals: Some(
            vec![
                "acquisition-theft".to_string(),
                "harassment".to_string(),
                "damage".to_string(),
            ],
        ),
        primary_motivation: None,
        secondary_motivations: None,
    };
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}