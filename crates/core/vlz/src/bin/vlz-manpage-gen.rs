// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::Write as _;

include!(concat!(env!("OUT_DIR"), "/constants.rs"));

fn strip_existing_spdx_header(content: &str) -> String {
    let spdx_copyright_prefix = format!(".\\\" SPDX-{}:", "FileCopyrightText");
    let spdx_license_prefix = format!(".\\\" SPDX-{}:", "License-Identifier");
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 4 {
        return content.to_string();
    }
    if !lines[0].starts_with(&spdx_copyright_prefix) {
        return content.to_string();
    }
    if lines[1] != ".\\\"" {
        return content.to_string();
    }
    if !lines[2].starts_with(&spdx_license_prefix) {
        return content.to_string();
    }
    if lines[3] != ".\\\"" {
        return content.to_string();
    }
    let mut start = 4;
    if lines.get(4).copied() == Some("") {
        start = 5;
    }
    content
        .split('\n')
        .skip(start)
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_with_generated_spdx_header(content: &str) -> String {
    let body = strip_existing_spdx_header(content);
    let mut out = String::new();
    let spdx_prefix = format!(".\\\" SPDX-{}: ", "License-Identifier");
    out.push_str(&format!(
        ".\\\" SPDX-FileCopyrightText: {}\n",
        MANPAGE_SPDX_COPYRIGHT
    ));
    out.push_str(".\\\"\n");
    out.push_str(&spdx_prefix);
    out.push_str(MANPAGE_SPDX_LICENSE);
    out.push('\n');
    out.push_str(".\\\"\n\n");
    out.push_str(&body);
    out
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string("man/vlz.1")?;
    let rendered = render_with_generated_spdx_header(content.as_str());
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(rendered.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spdx_license_line(value: &str) -> String {
        format!(".\\\" SPDX-{}: {}", "License-Identifier", value)
    }

    fn spdx_copyright_line(value: &str) -> String {
        format!(".\\\" SPDX-{}: {}", "FileCopyrightText", value)
    }

    #[test]
    fn manpage_spdx_constants_are_not_empty() {
        assert!(!MANPAGE_SPDX_COPYRIGHT.trim().is_empty());
        assert!(!MANPAGE_SPDX_LICENSE.trim().is_empty());
    }

    #[test]
    fn generator_source_has_no_hardcoded_output_spdx_header_lines() {
        let src = include_str!("vlz-manpage-gen.rs");
        assert!(!src.contains(".\\\" SPDX-FileCopyrightText: 2026"));
        let spdx_license_identifier =
            format!("SPDX-{}:", "License-Identifier");
        assert!(!src.contains(&format!(".\\\" {}", spdx_license_identifier)));
    }

    #[test]
    fn strip_existing_spdx_header_returns_input_when_too_short() {
        let input = "one\ntwo\nthree";
        assert_eq!(strip_existing_spdx_header(input), input);
    }

    #[test]
    fn strip_existing_spdx_header_returns_input_when_first_line_not_spdx() {
        let input = format!(
            ".TH VLZ 1\n.\\\"\n{}\n.\\\"\nbody",
            spdx_license_line("GPL-3.0-or-later")
        );
        assert_eq!(strip_existing_spdx_header(input.as_str()), input);
    }

    #[test]
    fn strip_existing_spdx_header_returns_input_when_second_line_not_expected()
    {
        let input = format!(
            "{}\nnot-comment\n{}\n.\\\"\nbody",
            spdx_copyright_line("Someone"),
            spdx_license_line("GPL-3.0-or-later")
        );
        assert_eq!(strip_existing_spdx_header(input.as_str()), input);
    }

    #[test]
    fn strip_existing_spdx_header_returns_input_when_third_line_not_spdx_license()
     {
        let input = format!(
            "{}\n.\\\"\n.TH VLZ 1\n.\\\"\nbody",
            spdx_copyright_line("Someone")
        );
        assert_eq!(strip_existing_spdx_header(input.as_str()), input);
    }

    #[test]
    fn strip_existing_spdx_header_returns_input_when_fourth_line_not_expected()
    {
        let input = format!(
            "{}\n.\\\"\n{}\nnot-comment\nbody",
            spdx_copyright_line("Someone"),
            spdx_license_line("GPL-3.0-or-later")
        );
        assert_eq!(strip_existing_spdx_header(input.as_str()), input);
    }

    #[test]
    fn strip_existing_spdx_header_strips_header_without_extra_blank_line() {
        let input = format!(
            "{}\n.\\\"\n{}\n.\\\"\n.TH VLZ 1\n.SH NAME",
            spdx_copyright_line("Someone"),
            spdx_license_line("GPL-3.0-or-later")
        );
        assert_eq!(
            strip_existing_spdx_header(input.as_str()),
            ".TH VLZ 1\n.SH NAME"
        );
    }

    #[test]
    fn strip_existing_spdx_header_strips_header_with_extra_blank_line() {
        let input = format!(
            "{}\n.\\\"\n{}\n.\\\"\n\n.TH VLZ 1\n.SH NAME",
            spdx_copyright_line("Someone"),
            spdx_license_line("GPL-3.0-or-later")
        );
        assert_eq!(
            strip_existing_spdx_header(input.as_str()),
            ".TH VLZ 1\n.SH NAME"
        );
    }

    #[test]
    fn render_with_generated_spdx_header_replaces_existing_header() {
        let input = format!(
            "{}\n.\\\"\n{}\n.\\\"\n.TH VLZ 1",
            spdx_copyright_line("old"),
            spdx_license_line("old")
        );
        let rendered = render_with_generated_spdx_header(input.as_str());
        assert!(rendered.contains(MANPAGE_SPDX_COPYRIGHT));
        assert!(rendered.contains(MANPAGE_SPDX_LICENSE));
        assert!(!rendered.contains(&spdx_copyright_line("old")));
        assert!(!rendered.contains(&spdx_license_line("old")));
        assert!(rendered.contains(".TH VLZ 1"));
    }

    #[test]
    fn render_with_generated_spdx_header_keeps_body_when_no_existing_header() {
        let input = ".TH VLZ 1\n.SH NAME\nvlz";
        let rendered = render_with_generated_spdx_header(input);
        assert!(rendered.contains(MANPAGE_SPDX_COPYRIGHT));
        assert!(rendered.contains(MANPAGE_SPDX_LICENSE));
        assert!(rendered.ends_with(input));
    }
}
