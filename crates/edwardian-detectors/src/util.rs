use edwardian_core::Location;

pub(crate) fn lines(content: &str) -> Vec<(usize, &str)> {
    content
        .split('\n')
        .enumerate()
        .map(|(i, l)| (i + 1, l.strip_suffix('\r').unwrap_or(l)))
        .collect()
}

/// 1-based byte column of the first occurrence of `token` in `line`.
pub(crate) fn col_of(line: &str, token: &str) -> Option<usize> {
    line.find(token).map(|i| i + 1)
}

/// All 1-based byte columns where `token` occurs.
pub(crate) fn cols_of(line: &str, token: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = line[from..].find(token) {
        out.push(from + i + 1);
        from += i + token.len();
    }
    out
}

/// True when the occurrence of `token` at byte index `idx` starts on a word
/// boundary (previous char is not alphanumeric/underscore).
pub(crate) fn boundary_before(line: &str, idx: usize) -> bool {
    idx == 0
        || !line[..idx]
            .chars()
            .last()
            .map(|c| c.is_alphanumeric() || c == '_')
            .unwrap_or(false)
}

/// True when `token` occurs as a whole word (bounded on both sides).
pub(crate) fn contains_word(line: &str, token: &str) -> bool {
    let mut from = 0;
    while let Some(i) = line[from..].find(token) {
        let idx = from + i;
        let after_ok = line[idx + token.len()..]
            .chars()
            .next()
            .map(|c| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(true);
        if boundary_before(line, idx) && after_ok {
            return true;
        }
        from = idx + 1;
        if from >= line.len() {
            break;
        }
    }
    false
}

/// True when `token` occurs immediately after an opening quote, i.e. inside a
/// string literal.
pub(crate) fn in_string_literal(line: &str, token: &str) -> Option<usize> {
    for q in ['"', '\''] {
        let needle = format!("{}{}", q, token);
        if let Some(i) = line.find(&needle) {
            return Some(i + 1);
        }
    }
    None
}

/// Skip obvious comment lines. `#` is treated as a comment leader only for
/// languages where it cannot start meaningful code (Python/Ruby/Perl).
pub(crate) fn is_comment(line: &str, path: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') || {
        let hash_lang = path.ends_with(".py") || path.ends_with(".rb") || path.ends_with(".pl");
        hash_lang && t.starts_with('#')
    }
}

pub(crate) fn loc(path: &str, line: usize, col: usize) -> Location {
    Location::new(path, line, col)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cols_are_one_based() {
        assert_eq!(col_of("foo bar", "bar"), Some(5));
        assert_eq!(cols_of("a a a", "a"), vec![1, 3, 5]);
    }

    #[test]
    fn word_boundaries() {
        assert!(contains_word("run bash now", "bash"));
        assert!(!contains_word("run bashful now", "bash"));
        assert!(!contains_word("use std::hash::", "sh"));
        assert!(contains_word("sh script.sh", "sh"));
    }

    #[test]
    fn literal_detection() {
        assert_eq!(in_string_literal("let p = \"/etc/x\";", "/etc/"), Some(9));
        assert!(in_string_literal("path = /etc/x", "/etc/").is_none());
    }

    #[test]
    fn comment_rules() {
        assert!(is_comment("// /bin/bash", "a.rs"));
        assert!(!is_comment("#!/bin/sh", "a.sh"));
        assert!(is_comment("# /bin/bash", "a.py"));
        assert!(!is_comment("# /bin/bash", "a.sh"));
    }
}
