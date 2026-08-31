#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    let displayed = execwake::display_text::sanitize(input);
    assert!(!displayed.chars().any(char::is_control));
});
