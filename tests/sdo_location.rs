use chrono::{DateTime, Utc};
use stix4rust::core::sdos::location::Location;

/// A complete deserialization of the object grabbing values for each and every element.
#[test]
fn it_stix_object_complete_deserialization() {
    let text = r#"
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
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
        "region": "south-eastern-asia",
        "country": "th",
        "administrative_area": "Tak",
        "postal_code": "63170"
    }
    "#;
    let _object: Location = serde_json::from_str(text).unwrap();
}

/// A complete deserialization of a JSON object that has duplicate keys.
#[test]
#[should_panic]
fn it_stix_object_complete_deserialization_with_duplicate_key() {
    let text = r#"
    {
        "type": "location",
        "spec_version": "2.1",
        "spec_version": "2.1",
        "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
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
        "region": "south-eastern-asia",
        "country": "th",
        "administrative_area": "Tak",
        "postal_code": "63170"
    }
    "#;
    let _object: Location = serde_json::from_str(text).unwrap();
}

/// A complete deserialization attempt that SHOULD fail because of a syntax error
#[test]
#[should_panic]
fn it_stix_object_syntax_error_complete_deserialization() {
    let text = r#"
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
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
        "region": "south-eastern-asia",
        "country": "th",
        "administrative_area": "Tak",
        "postal_code": "63170"
    }
    "#;
    let _object: Location = serde_json::from_str(text).unwrap();
}

/// Deserialization of an object with only the required fields. In this case, it SHOULD panic since any of the locations attachment SHOULD BE provided.
#[test]
#[should_panic]
fn  it_object_deserialization_with_required_fields_only() {
    let text = r#"
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
    }
    "#;
    let _object: Location = serde_json::from_str(text).unwrap();
}

/// Deserialization of a Location without the longitude. It SHOULD panic since when `location` is provided, `longitude`, `latitude` and `precision` SHOULD be provided as well.
#[test]
#[ignore = "not yet implemented"]
#[should_panic]
fn  it_location_deserialization_with_missing_longitude() {
    let text = r#"
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "latitude": 0,
        "precision": 0
    }
    "#;
    let _object: Location = serde_json::from_str(text).unwrap();
}

/// Deserialization of a Location without the latitude. It SHOULD panic since when `location` is provided, `longitude`, `latitude` and `precision` SHOULD be provided as well.
#[test]
#[ignore = "not yet implemented"]
#[should_panic]
fn  it_location_deserialization_with_missing_latitude() {
    let text = r#"
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "longitude": 0,
        "precision": 0
    }
    "#;
    let _object: Location = serde_json::from_str(text).unwrap();
}


/// Deserialization of a Location without precision. It SHOULD panic since when `location` is provided, `longitude`, `latitude` and `precision` SHOULD be provided as well.
#[test]
#[ignore = "not yet implemented"]
#[should_panic]
fn  it_location_deserialization_with_missing_precision() {
    let text = r#"
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "longitude": 0,
        "latitude": 0
    }
    "#;
    let _object: Location = serde_json::from_str(text).unwrap();
}

/// Deserialization of a Location with invalid longitude value.
#[test]
#[ignore = "not yet implemented"]
#[should_panic]
fn  it_location_deserialization_with_invalid_longitude() {
    let text = r#"
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "longitude": -400.0,
        "latitude": 0,
        "precision": 0
    }
    "#;
    let _object: Location = serde_json::from_str(text).unwrap();
}

/// Deserialization of a Location with invalid latitude value.
#[test]
#[ignore = "not yet implemented"]
#[should_panic]
fn  it_location_deserialization_with_invalid_latitude() {
    let text = r#"
    {
        "type": "location",
        "spec_version": "2.1",
        "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "longitude": 0,
        "latitude": -200.0,
        "precision": 0
    }
    "#;
    let _object: Location = serde_json::from_str(text).unwrap();
}


/// Serialization test of the object with certain values for the object.
/// Note that STIX 2.1 requires null values not appear in the object. This test verifies that optional values are not shown.
#[test]
fn  it_stix_object_serialization() {
    let object =     Location {
        id: "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64".to_string(),
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
        name: None,
        description: None,
        latitude: None,
        longitude: None,
        precision: None,
        region: Some(
            "south-eastern-asia".to_string(),
        ),
        country: Some(
            "th".to_string(),
        ),
        administrative_area: Some(
            "Tak".to_string(),
        ),
        city: None,
        street_address: None,
        postal_code: Some(
            "63170".to_string(),
        ),
    }
    ;
    println!("{}", serde_json::to_string_pretty(&object).unwrap());
}