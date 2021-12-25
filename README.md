# STIX 4 Rust

A Rust crate that aspires to implement the [Stix 2.1](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html) CTI standard.

# Disclaimer

This is a work-in-progress and **APIs may change at any time**. 
By no means the code included in this repository SHOULD be considered final until the code is released as a Crate and this message is removed from this repository.

If you currently need STIX capabilities in Rust you might find useful [this crate](https://crates.io/crates/stix/0.3.0) instead. 
Use it under your own responsibility.

## Installation

The crate is installed and coded with Cargo in mind. 
The [Cargo Book](https://doc.rust-lang.org/cargo/commands/package-commands.html) is a good entry point to install it in your system.
To install the development version of this package you WILL need it.

```
$ cargo --version
cargo 1.53.0
```

Afterwards, clone the repository and run the application and/or tests:

```
$ git clone https://github.com/febrezo/stix4rust
$ cd stix4rust
$ cargo test
```

