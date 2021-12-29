use chrono::{DateTime, Utc};
use stix4rust::core::sdos::tool::Tool;
use stix4rust::core::types::{
    ExternalReference,
    GranularMarking,
    KillChainPhase
};

/// A complete deserialization of the object grabbing values for each and every element.
#[test]
fn it_tool_complete_deserialization() {
    let text = r#"
    {
        "type": "tool",
        "spec_version": "2.1",
        "id": "tool--984fe0d8-689e-11ec-a650-3b8a7f05cbbd",
        "created": "2014-12-30T23:53:00.000Z",
        "modified": "2021-11-24T04:07:00.000Z",
        "created_by_ref": "identity--a0201c24-689e-11ec-b547-57479a05b2eb",
        "revoked": false,
        "confidence": 100,
        "labels": ["osint"],
        "external_references": [
            {
                "source_name": "Github",
                "url": "https://github.com/i3visio/osrframework"
            }
        ],
        "granular_markings": [
            {
                "lang": "es",
                "selectors": ["sel1", "sel2"]
            }
        ],
        "object_marking_refs": [],
        "name": "OSRFramework",
        "description": "A tool to collect information from open sources.",
        "tool_types": ["information-gathering"],
        "aliases": ["usufy", "searchfy", "mailfy", "domainfy"],
        "kill_chain_phases": [
            {
                "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                "phase_name": "reconnaissance"
            }
        ],
        "tool_version": "0.21.0"
    }
    "#;
    let _object: Tool = serde_json::from_str(text).unwrap();
}

/// A complete deserialization attempt that SHOULD fail because of a syntax error
#[test]
#[should_panic]
fn it_tool_syntax_error_complete_deserialization() {
    let text = r#"
    {
        "type": "tool",
        "spec_version": "2.1",
        "id": "tool--984fe0d8-689e-11ec-a650-3b8a7f05cbbd",
        "created": "2014-12-30T23:53:00.000Z",
        "modified": "2021-11-24T04:07:00.000Z",
        "created_by_ref": "identity--a0201c24-689e-11ec-b547-57479a05b2eb",
        "revoked": false,
        "confidence": 100,
        "labels": ["syntax-error",
        "external_references": [
            {
                "source_name": "Github",
                "url": "https://github.com/i3visio/osrframework"
            }
        ],
        "granular_markings": [
            {
                "lang": "es",
                "selectors": ["sel1", "sel2"]
            }
        ],
        "object_marking_refs": [],
        "name": "OSRFramework",
        "description": "A tool to collect information from open sources.",
        "tool_types": ["information-gathering"],
        "aliases": ["usufy", "searchfy", "mailfy", "domainfy"],
        "kill_chain_phases": [
            {
                "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                "phase_name": "reconnaissance"
            }
        ],
        "tool_version": "0.21.0"
    }
    "#;
    let _object: Tool = serde_json::from_str(text).unwrap();
}


/// A complete deserialization of a JSON object that has duplicate keys.
#[test]
#[should_panic]
fn it_tool_complete_deserialization_with_duplicate_keys() {
    let text = r#"
    {
        "type": "tool",
        "spec_version": "2.1",
        "id": "tool--984fe0d8-689e-11ec-a650-3b8a7f05cbbd",
        "created": "2014-12-30T23:53:00.000Z",
        "modified": "2021-11-24T04:07:00.000Z",
        "created_by_ref": "identity--a0201c24-689e-11ec-b547-57479a05b2eb",
        "created_by_ref": "identity--a0201c24-689e-11ec-b547-57479a05b2eb",
        "revoked": false,
        "confidence": 100,
        "labels": ["osint"],
        "external_references": [
            {
                "source_name": "Github",
                "url": "https://github.com/i3visio/osrframework"
            }
        ],
        "granular_markings": [
            {
                "lang": "es",
                "selectors": ["sel1", "sel2"]
            }
        ],
        "object_marking_refs": [],
        "name": "OSRFramework",
        "description": "A tool to collect information from open sources.",
        "tool_types": ["information-gathering"],
        "aliases": ["usufy", "searchfy", "mailfy", "domainfy"],
        "kill_chain_phases": [
            {
                "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                "phase_name": "reconnaissance"
            }
        ],
        "tool_version": "0.21.0"
    }
    "#;
    let _object: Tool = serde_json::from_str(text).unwrap();
}


/// Deserialization of a vulnerability with only the required fields.
#[test]
fn it_tool_deserialization_with_required_fields_only() {
    let text = r#"
    {
        "type": "tool",
        "spec_version": "2.1",
        "id": "tool--984fe0d8-689e-11ec-a650-3b8a7f05cbbd",
        "created": "2014-12-30T23:53:00.000Z",
        "modified": "2021-11-24T04:07:00.000Z",
        "created_by_ref": "identity--a0201c24-689e-11ec-b547-57479a05b2eb",
        "name": "OSRFramework",
        "tool_types": ["information-gathering"]
    }
    "#;
    let _object: Tool = serde_json::from_str(text).unwrap();
}

/// Since there are some fields which are required, this test verifies that the deserialization method effectively detects that a panics.
#[test]
#[should_panic]
fn it_tool_deserialization_with_missing_required_field() {
    let text = r#"
    {
        "type": "tool",
        "spec_version": "2.1",
        "id": "tool--984fe0d8-689e-11ec-a650-3b8a7f05cbbd",
        "created": "2014-12-30T23:53:00.000Z",
        "modified": "2021-11-24T04:07:00.000Z",
        "created_by_ref": "identity--a0201c24-689e-11ec-b547-57479a05b2eb",
        "name": "OSRFramework"
    }
    "#;
    let object: Tool = serde_json::from_str(text).unwrap();
    println!("{:#?}", object);
}

/// Serialization test of the object with certain values for the object.
#[test]
fn it_tool_complete_serialization() {
    let object = Tool {
        id: "tool--984fe0d8-689e-11ec-a650-3b8a7f05cbbd".to_string(),
        spec_version: "2.1".to_string(),
        created: DateTime::parse_from_rfc3339("2014-12-30T23:53:00Z").unwrap().with_timezone(&Utc),
        modified: DateTime::parse_from_rfc3339("2021-11-24T04:07:00Z").unwrap().with_timezone(&Utc),
        created_by_ref: Some(
            "identity--a0201c24-689e-11ec-b547-57479a05b2eb".to_string(),
        ),
        revoked: Some(
            false,
        ),
        labels: Some(
            vec![
                "osint".to_string(),
            ],
        ),
        confidence: Some(100),
        lang: Some("en".to_string()),
        external_references: Some(
            vec![
                ExternalReference {
                    source_name: "Github".to_string(),
                    description: None,
                    url: Some(
                        "https://github.com/i3visio/osrframework".to_string(),
                    ),
                    hashes: None,
                    external_id: None,
                },
            ],
        ),
        object_marking_refs: Some(
            vec![],
        ),
        granular_markings: Some(
            vec![
                GranularMarking {
                    lang: Some(
                        "es".to_string(),
                    ),
                    marking_ref: None,
                    selectors: vec![
                        "sel1".to_string(),
                        "sel2".to_string(),
                    ],
                },
            ],
        ),
        name: "OSRFramework".to_string(),
        description: Some(
            "A tool to collect information from open sources.".to_string()
        ),
        tool_types: vec![
            "information-gathering".to_string(),
        ],
        aliases: Some(
            vec![
                "usufy".to_string(),
                "searchfy".to_string(),
                "mailfy".to_string(),
                "domainfy".to_string(),
            ],
        ),
        kill_chain_phases: Some(
            vec![
                KillChainPhase {
                    kill_chain_name: "lockheed-martin-cyber-kill-chain".to_string(),
                    phase_name: "reconnaissance".to_string(),
                },
            ],
        ),
        tool_version: Some(
            "0.21.0".to_string(),
        ),
    };
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}

/// Stix 2.1 requires null values not appear in the object. This test verifies that optional values are not shown.
#[test]
fn it_tool_serialization_without_optional_attributes() {
    let object = Tool {
        id: "tool--984fe0d8-689e-11ec-a650-3b8a7f05cbbd".to_string(),
        spec_version: "2.1".to_string(),
        created: DateTime::parse_from_rfc3339("2014-12-30T23:53:00Z").unwrap().with_timezone(&Utc),
        modified: DateTime::parse_from_rfc3339("2021-11-24T04:07:00Z").unwrap().with_timezone(&Utc),
        created_by_ref: Some(
            "identity--a0201c24-689e-11ec-b547-57479a05b2eb".to_string(),
        ),
        revoked: None,
        labels: None,
        confidence: None,
        lang: None,
        external_references: None,
        object_marking_refs: None,
        granular_markings: None,
        name: "OSRFramework".to_string(),
        description: None,
        tool_types: vec![
            "information-gathering".to_string(),
        ],
        aliases: None,
        kill_chain_phases: None,
        tool_version: None,
    };   
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}
