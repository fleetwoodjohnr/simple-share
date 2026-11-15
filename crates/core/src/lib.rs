//! Simple Share core. Everything that faces the network or untrusted input
//! lives here so it can be tested without the UI.
pub mod mdns;
pub mod save;
pub mod server;
pub mod tls;
