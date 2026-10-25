//! The offline bundle on the wire (spec §7): a JSON array of full Nostr
//! events. Reading verifies every signature before anything is looked at.

use nostr_sdk::Event;
use pubpki_core::MAX_BUNDLE_EVENTS;

/// Parse a bundle; every event's signature must verify. The size bound
/// comes before the signatures, so an oversized file costs no checks.
pub fn parse(json: &str) -> Result<Vec<Event>, String> {
    let events: Vec<Event> = serde_json::from_str(json).map_err(|e| format!("bundle: {e}"))?;
    if events.len() > MAX_BUNDLE_EVENTS {
        return Err(format!("bundle: more than {MAX_BUNDLE_EVENTS} events"));
    }
    for (i, ev) in events.iter().enumerate() {
        ev.verify()
            .map_err(|e| format!("bundle event {i}: bad signature: {e}"))?;
    }
    Ok(events)
}

pub fn render(events: &[Event]) -> Result<String, String> {
    serde_json::to_string_pretty(events).map_err(|e| e.to_string())
}
