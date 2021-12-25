pub mod patterns;
pub mod scos;
pub mod sdos;
pub mod sros;
pub mod types;


/// This trait implements the basic functionalities for STIX objects.
pub trait STIXObject {
    // fn build_new_id_for_type(&self, obj_type: String) -> String {
    //     format!("{}--{}", obj_type, Uuid::new_v4())
    // }
    // fn is_non_standard_stix_type(&self) -> bool {
    //     self.type.starts_with("x-")
    // }
    // fn is_same_object_as(&self, id: String) -> bool {
    //     self.id == id
    // }
    // fn new_from_json_text(&self, json_text: String) -> Self;
    // fn serialize(&self) -> String {
    //     let serialized_obj = serde_json::to_string(self).unwrap();
    //     serialized_obj
    // }
    // fn matches_stix_type(&self, new_type: String) -> bool {
    //     self.type == new_type
    // }
}