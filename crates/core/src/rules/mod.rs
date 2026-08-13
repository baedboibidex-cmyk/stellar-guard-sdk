//! Rule registry. Each rule lives in its own module and exposes a `run`
//! entry point; the engine invokes every enabled rule on each parsed file.
//! [`common`] holds the analysis primitives shared between rules.

pub mod common;
pub mod sg001;
pub mod sg002;
