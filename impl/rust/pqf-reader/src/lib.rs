//! Independent Rust implementation of the PostQuantum.FileFormat (PQF) v1
//! reader.
//!
//! This crate is an intentional second-source for the PQF on-the-wire
//! contract. It deliberately does **not** share code with the .NET reference
//! implementation: it has its own deterministic CBOR validator, its own
//! header-schema enforcement, its own recipient trial loop, and uses
//! independently-maintained Rust crypto crates (RustCrypto + dalek) for the
//! primitives.
//!
//! The point is to detect specification bugs that would otherwise be
//! invisible — anything where two implementations disagree about what the
//! spec says is, by definition, a spec defect or an implementation defect.
//!
//! Scope: this is a **reader-only** implementation. It does not encrypt,
//! does not sign, does not generate keys. It exists to validate and decrypt
//! files produced by the .NET reference implementation against the PQF v1
//! conformance vector set.

pub mod cbor;
pub mod error;
pub mod header;
pub mod identity;
pub mod reader;

pub use error::{PqfError, RefusalReason, Result};
pub use header::{Alg, Header, RecipientEntry, SignerEntry};
pub use identity::Identity;
pub use reader::{decrypt, parse, ParsedFile};
