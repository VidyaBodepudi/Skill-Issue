use regex::Regex;
use std::sync::OnceLock;

fn secret_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            Regex::new(r#"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[^'\"\s,;}]+"#)
                .expect("valid secret assignment regex"),
            Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid aws key regex"),
            Regex::new(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----").expect("valid private key regex"),
        ]
    })
}

pub fn redact(input: &str) -> String {
    secret_patterns()
        .iter()
        .fold(input.to_owned(), |redacted, pattern| {
            pattern.replace_all(&redacted, "[REDACTED]").to_string()
        })
}

pub fn evidence_snippet(content: &str, needle: &str, context_chars: usize) -> String {
    let Some(index) = content.to_lowercase().find(&needle.to_lowercase()) else {
        return redact(needle);
    };
    let start = index.saturating_sub(context_chars);
    let end = (index + needle.len() + context_chars).min(content.len());
    redact(content.get(start..end).unwrap_or(needle)).replace('\n', " ")
}
