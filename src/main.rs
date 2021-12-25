pub mod core;

use std::fs;
use std::error::Error;
use argparse::{
    ArgumentParser, 
    StoreTrue, 
    Store
};
use crate::core::sdos::SDO;

fn main() -> Result<(), Box<dyn Error>> {
    let mut verbose = false;
    let mut input_file: String = "".to_string();
    let mut output_file: String = "./output.stix".to_string();
    { 
        let mut parser = ArgumentParser::new();
        parser.set_description("A STIX parsing crate.");
        parser.refer(&mut input_file)
            .add_option(
                &["-i", "--input-file"], 
                Store,
                "The input file to parse."
            ).required();
        parser.refer(&mut output_file)
            .add_option(
                &["-o", "--output-file"], 
                Store,
                "The output file where the information will be stored"
            );
        parser.refer(&mut verbose)
            .add_option(
                &["-v", "--verbose"], 
                StoreTrue,
                "Whether to print information in the terminal or not"
            );
        parser.parse_args_or_exit();
    }

    println!("> Reading STIX file from '{}'…", input_file);
    let text = fs::read_to_string(input_file).expect("Unable to read file");
    if verbose {
        println!("> Content read:\n'{}'", text);
    }
    if verbose {
        println!("> Trying to deserialize STIX content…");
    }
    let object: SDO = serde_json::from_str(&text).unwrap();
    if verbose {
        println!("> Deserialized Object:\n{:#?}", object);
    }
    if verbose {
        println!("> Trying to re-serialize STIX object…");
    }
    let new_content = serde_json::to_string_pretty(&object).unwrap();
    if verbose {
        println!("> Serialized Object:\n{}", new_content);
    }
    println!("> Storing STIX content onto '{}'…", output_file);
    fs::write(output_file, new_content).expect("Unable to write file");
    Ok(())
}