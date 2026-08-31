use std::fmt::Write;

use crate::limits::MAX_DISPLAY_TEXT_BYTES;

pub fn sanitize(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(MAX_DISPLAY_TEXT_BYTES));
    let mut consumed = 0;

    for character in value.chars() {
        let replacement = replacement(character);
        let additional = replacement
            .as_ref()
            .map_or_else(|| character.len_utf8(), String::len);
        if output.len().saturating_add(additional) > MAX_DISPLAY_TEXT_BYTES {
            break;
        }
        if let Some(replacement) = replacement {
            output.push_str(&replacement);
        } else {
            output.push(character);
        }
        consumed += character.len_utf8();
    }

    if consumed < value.len() {
        write!(
            output,
            "… [truncated {} bytes]",
            value.len().saturating_sub(consumed)
        )
        .expect("writing to a string cannot fail");
    }
    output
}

fn replacement(character: char) -> Option<String> {
    if html_metacharacter(character)
        || character.is_control()
        || directional_control(character)
        || invisible_format_control(character)
    {
        Some(format!("\\u{{{:04x}}}", character as u32))
    } else {
        None
    }
}

const fn html_metacharacter(character: char) -> bool {
    matches!(character, '<' | '>' | '&')
}

const fn directional_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

const fn invisible_format_control(character: char) -> bool {
    matches!(character, '\u{200b}'..='\u{200d}' | '\u{2060}' | '\u{feff}')
}

#[cfg(test)]
mod tests {
    use super::sanitize;
    use crate::limits::MAX_DISPLAY_TEXT_BYTES;

    #[test]
    fn makes_markup_terminal_sequences_and_bidi_visible() {
        let input = "<script>&style</script>\u{1b}]8;;https://example.test\u{7}link\u{1b}]8;;\u{7}\u{202e}txt";
        let output = sanitize(input);

        assert_eq!(
            output,
            "\\u{003c}script\\u{003e}\\u{0026}style\\u{003c}/script\\u{003e}\\u{001b}]8;;https://example.test\\u{0007}link\\u{001b}]8;;\\u{0007}\\u{202e}txt"
        );
        assert!(!output.chars().any(char::is_control));
        assert!(!output.contains('\u{202e}'));
    }

    #[test]
    fn bounds_the_display_copy_without_splitting_utf8() {
        let input = "界".repeat(MAX_DISPLAY_TEXT_BYTES);
        let output = sanitize(&input);

        assert!(output.starts_with('界'));
        assert!(output.contains("[truncated "));
        assert!(output.len() < MAX_DISPLAY_TEXT_BYTES + 64);
    }
}
