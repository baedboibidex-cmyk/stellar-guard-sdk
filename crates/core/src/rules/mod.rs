//! Rule registry. Each rule lives in its own module and exposes a `run`
//! entry point; the engine invokes every enabled rule on each parsed file.

pub mod sg001;
