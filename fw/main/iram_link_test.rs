//! Private, opt-in linker experiment. No changes to the SDK source files.
pub fn place_quic_hot_functions(script: &str) -> Result<String, &'static str> {
    let marker = "*(.iram1 .iram1.*)";
    if script.matches(marker).count() != 1 {
        return Err("expected one SDK IRAM collector");
    }
    Ok(script.replacen(marker,
        "*(.iram1 .iram1.*)\n *(.text.*quic_lite*receive_ack_packet_on_path*)\n *(.text.*quic_lite*next_bearer_deadline*)", 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_sdk_heap_and_other_sections() {
        let original = "SECTIONS { .iram0.text : { START; *(.iram1 .iram1.*) END; } HEAP; FLASH; }";
        let changed = place_quic_hot_functions(original).unwrap();
        assert!(changed.contains("START; *(.iram1 .iram1.*)"));
        assert!(changed.ends_with(" END; } HEAP; FLASH; }"));
        assert_eq!(changed.matches(".iram0.text").count(), 1);
        assert_eq!(changed.matches("receive_ack_packet_on_path").count(), 1);
        assert_eq!(changed.matches("next_bearer_deadline").count(), 1);
    }

    #[test]
    fn rejects_missing_or_ambiguous_sdk_layout() {
        assert!(place_quic_hot_functions("FLASH").is_err());
        assert!(place_quic_hot_functions("*(.iram1 .iram1.*) *(.iram1 .iram1.*)").is_err());
    }
}
