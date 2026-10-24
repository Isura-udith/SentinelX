//! SentinelX Application library exposing pipeline coordination, telemetry scheduling,
//! state management, and Tauri commands.

#![allow(missing_docs)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]

pub mod commands;
pub mod errors;
pub mod events;
pub mod pipeline;
pub mod state;
pub mod telemetry;

#[cfg(test)]
mod tests;
