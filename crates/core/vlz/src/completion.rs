// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Post-process clap_complete output to omit deprecated aliases.

use clap_complete::Shell;

use crate::cli_values::COMPLETION_OMIT_ALIASES;

/// Filter generated completion script bytes for `shell`.
///
/// Deprecated aliases in [`COMPLETION_OMIT_ALIASES`] are removed entirely so
/// TAB completion suggests preferred names only. Runtime parsing is unchanged.
pub fn filter_completion_output(shell: Shell, bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(bytes);
    let filtered = match shell {
        Shell::Bash => filter_bash(&text),
        Shell::Zsh => filter_zsh(&text),
        Shell::Fish => filter_fish(&text),
        // Project only ships bash/zsh/fish; leave other shells unfiltered.
        _ => text.into_owned(),
    };
    filtered.into_bytes()
}

fn is_omitted_token(token: &str) -> bool {
    for alias in COMPLETION_OMIT_ALIASES {
        if *alias == "list" {
            // Omit languages subcommand alias only; keep config --list.
            if token == "list" {
                return true;
            }
            continue;
        }
        if token == *alias || token == format!("--{alias}") {
            return true;
        }
    }
    false
}

fn filter_opts_line(line: &str) -> String {
    // opts="... tokens ..."
    let Some(eq) = line.find('=') else {
        return line.to_string();
    };
    let (prefix, rest) = line.split_at(eq + 1);
    let rest = rest.trim();
    let (quote, inner) = if let Some(s) = rest.strip_prefix('"') {
        ('"', s.strip_suffix('"').unwrap_or(s))
    } else if let Some(s) = rest.strip_prefix('\'') {
        ('\'', s.strip_suffix('\'').unwrap_or(s))
    } else {
        return line.to_string();
    };
    let filtered: Vec<&str> = inner
        .split_whitespace()
        .filter(|t| !is_omitted_token(t))
        .collect();
    format!("{prefix}{quote}{}{quote}", filtered.join(" "))
}

/// Drop a bash/zsh `case` arm starting at `start` (index of the pattern line).
/// Returns the index of the first line after the arm's `;;`.
fn skip_case_arm(lines: &[&str], start: usize) -> usize {
    let mut i = start + 1;
    while i < lines.len() {
        if lines[i].trim() == ";;" {
            return i + 1;
        }
        i += 1;
    }
    lines.len()
}

fn ensure_config_list_in_opts(line: &str) -> String {
    if line.contains("--list") {
        return line.to_string();
    }
    if let Some(idx) = line.find("--example") {
        let mut out = line.to_string();
        out.insert_str(idx + "--example".len(), " --list");
        return out;
    }
    line.to_string()
}

fn filter_bash(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        // Dispatch: vlz,list) -> languages
        if trimmed == "vlz,list)" {
            i = skip_case_arm(&lines, i);
            continue;
        }
        // Flag value arms for omitted long aliases
        if trimmed == "--summary-file)" || trimmed == "--exit-code-on-cve)" {
            i = skip_case_arm(&lines, i);
            continue;
        }
        if lines[i].contains("opts=") {
            let prev = i.checked_sub(1).map(|j| lines[j].trim()).unwrap_or("");
            let mut line = filter_opts_line(lines[i]);
            if prev == "vlz__subcmd__config)" {
                line = ensure_config_list_in_opts(&line);
            }
            out.push(line);
        } else {
            out.push(lines[i].to_string());
        }
        i += 1;
    }
    join_lines(&out, text.ends_with('\n'))
}

fn filter_zsh(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        // Alias-only case arm for the languages subcommand.
        if trimmed == "(list)" {
            i = skip_case_arm(&lines, i);
            continue;
        }
        // Subcommand table entry: 'list:...' but not 'list-providers:...'
        if trimmed.starts_with("'list:")
            && !trimmed.starts_with("'list-providers:")
        {
            i += 1;
            continue;
        }
        // Long-flag argument specs for omitted aliases.
        if trimmed.contains("--summary-file=")
            || trimmed.contains("--exit-code-on-cve=")
        {
            i += 1;
            continue;
        }
        let mut line = lines[i].to_string();
        // ::subcommand:(scan languages list config ...)
        if line.contains("::subcommand:(") {
            for alias in COMPLETION_OMIT_ALIASES {
                // Remove " alias" or "alias " as a whole word inside the paren list.
                let spaced = format!(" {alias} ");
                if let Some(idx) = line.find(&spaced) {
                    line.replace_range(idx..idx + alias.len() + 1, "");
                } else {
                    let leading = format!("({alias} ");
                    if let Some(idx) = line.find(&leading) {
                        line.replace_range(
                            idx + 1..idx + 1 + alias.len() + 1,
                            "",
                        );
                    } else {
                        let trailing = format!(" {alias})");
                        if let Some(idx) = line.find(&trailing) {
                            line.replace_range(idx..idx + alias.len() + 1, "");
                        }
                    }
                }
            }
        }
        out.push(line);
        i += 1;
    }
    join_lines(&out, text.ends_with('\n'))
}

fn filter_fish(text: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        // Top-level alias subcommand suggestion.
        if trimmed.contains("-a \"list\"")
            && trimmed.contains("__fish_vlz_needs_command")
        {
            continue;
        }
        // Alias-specific option completions (same as languages).
        if trimmed.contains("__fish_vlz_using_subcommand list\"")
            || trimmed.contains("__fish_vlz_using_subcommand list'")
        {
            continue;
        }
        let mut line = line.to_string();
        for alias in COMPLETION_OMIT_ALIASES {
            if *alias == "list" {
                continue; // handled by line drops above
            }
            let flag = format!(" -l {alias}");
            while let Some(idx) = line.find(&flag) {
                line.replace_range(idx..idx + flag.len(), "");
            }
        }
        out.push(line);
    }
    join_lines(&out, text.ends_with('\n'))
}

fn join_lines(lines: &[String], trailing_newline: bool) -> String {
    let mut s = lines.join("\n");
    if trailing_newline && !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omit_aliases_match_plan() {
        assert!(COMPLETION_OMIT_ALIASES.contains(&"list"));
        assert!(COMPLETION_OMIT_ALIASES.contains(&"summary-file"));
        assert!(COMPLETION_OMIT_ALIASES.contains(&"exit-code-on-cve"));
    }

    #[test]
    fn bash_injects_config_list_when_clap_omits_it() {
        let input = r#"
        vlz__subcmd__config)
            opts="-v -c -h --example --set --verbose --config --help"
            ;;
"#;
        let out = String::from_utf8(filter_completion_output(
            Shell::Bash,
            input.as_bytes(),
        ))
        .unwrap();
        assert!(out.contains("--list"));
    }

    #[test]
    fn bash_keeps_config_list_flag() {
        let input = r#"
        vlz__subcmd__config)
            opts="-v -c -h --example --list --set --verbose --config --help"
            ;;
"#;
        let out = String::from_utf8(filter_completion_output(
            Shell::Bash,
            input.as_bytes(),
        ))
        .unwrap();
        assert!(out.contains("--list"));
    }

    #[test]
    fn bash_removes_list_from_opts_keeps_list_providers() {
        let input = r#"
        vlz)
            opts="-v scan languages list config db list-providers"
            ;;
"#;
        let out = String::from_utf8(filter_completion_output(
            Shell::Bash,
            input.as_bytes(),
        ))
        .unwrap();
        assert!(out.contains("languages"));
        assert!(!out.contains(" list "));
        assert!(!out.contains("list config"));
        assert!(out.contains("list-providers"));
    }

    #[test]
    fn bash_removes_vlz_list_dispatch_arm() {
        let input = r#"
            vlz,languages)
                cmd="vlz__subcmd__languages"
                ;;
            vlz,list)
                cmd="vlz__subcmd__languages"
                ;;
            vlz,scan)
                cmd="vlz__subcmd__scan"
                ;;
"#;
        let out = String::from_utf8(filter_completion_output(
            Shell::Bash,
            input.as_bytes(),
        ))
        .unwrap();
        assert!(out.contains("vlz,languages)"));
        assert!(!out.contains("vlz,list)"));
        assert!(out.contains("vlz,scan)"));
    }

    #[test]
    fn bash_removes_summary_file_and_exit_code_on_cve() {
        let input = r#"
            opts="-s --report --summary-file --exit-code --exit-code-on-cve -j"
            case "${prev}" in
                --report)
                    COMPREPLY=()
                    ;;
                --summary-file)
                    COMPREPLY=()
                    return 0
                    ;;
                --exit-code)
                    COMPREPLY=()
                    ;;
                --exit-code-on-cve)
                    COMPREPLY=()
                    return 0
                    ;;
            esac
"#;
        let out = String::from_utf8(filter_completion_output(
            Shell::Bash,
            input.as_bytes(),
        ))
        .unwrap();
        assert!(out.contains("--report"));
        assert!(out.contains("--exit-code"));
        assert!(!out.contains("--summary-file"));
        assert!(!out.contains("--exit-code-on-cve"));
        assert!(out.contains("-j"));
    }

    #[test]
    fn zsh_removes_list_subcommand_and_flag_aliases() {
        let input = r#"
'::subcommand:(scan languages list config db fp preload help)' \
'list:List supported manifest languages' \
'languages:List supported manifest languages' \
'list-providers:List supported CVE providers' \
'*--report=[Write additional report files]:TYPE:PATH:_default' \
'*--summary-file=[Write additional report files]:TYPE:PATH:_default' \
'--exit-code=[Exit code]:CODE:_default' \
'--exit-code-on-cve=[Exit code]:CODE:_default' \
(list)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
&& ret=0
;;
(languages)
_arguments "${_arguments_options[@]}" : \
'-h[Print help]' \
&& ret=0
;;
"#;
        let out = String::from_utf8(filter_completion_output(
            Shell::Zsh,
            input.as_bytes(),
        ))
        .unwrap();
        assert!(out.contains("languages"));
        assert!(out.contains("list-providers"));
        assert!(!out.contains("'list:List"));
        assert!(!out.contains(" languages list "));
        assert!(out.contains("--report="));
        assert!(!out.contains("--summary-file="));
        assert!(out.contains("--exit-code="));
        assert!(!out.contains("--exit-code-on-cve="));
        assert!(!out.contains("(list)"));
        assert!(out.contains("(languages)"));
    }

    #[test]
    fn fish_removes_list_and_long_aliases() {
        let input = r#"
complete -c vlz -n "__fish_vlz_needs_command" -f -a "languages" -d 'List supported manifest languages'
complete -c vlz -n "__fish_vlz_needs_command" -f -a "list" -d 'List supported manifest languages'
complete -c vlz -n "__fish_vlz_using_subcommand scan" -s s -l report -l summary-file -d 'Write additional'
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l exit-code -l exit-code-on-cve -d 'Exit code'
complete -c vlz -n "__fish_vlz_using_subcommand list" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand languages" -s h -l help -d 'Print help'
"#;
        let out = String::from_utf8(filter_completion_output(
            Shell::Fish,
            input.as_bytes(),
        ))
        .unwrap();
        assert!(out.contains("-a \"languages\""));
        assert!(!out.contains("-a \"list\""));
        assert!(out.contains("-l report"));
        assert!(!out.contains("-l summary-file"));
        assert!(out.contains("-l exit-code"));
        assert!(!out.contains("-l exit-code-on-cve"));
        assert!(!out.contains("using_subcommand list\""));
        assert!(out.contains("using_subcommand languages\""));
    }
}
