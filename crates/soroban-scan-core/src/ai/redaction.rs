//! Redaction for assistance output.
//!
//! Assistance is the most likely place for accidental data exposure: evidence,
//! titles, and file paths come from an untrusted repository and are copied into
//! model prompts and human-readable guidance. This module applies a final,
//! deterministic redaction pass for common credential formats, secret-like
//! assignments, private keys, and absolute home directories.
//!
//! Redaction is intentionally conservative. Over-redacting a token-shaped word
//! is preferable to leaking a live credential.

/// Replacement marker for credentials and secret values.
pub const REDACTED: &str = "[REDACTED]";

/// Replacement marker for an absolute home directory.
pub const HOME: &str = "[HOME]";

/// Redacts secrets, environment-style assignments, and home paths in `text`.
///
/// The function is idempotent: redacting already-redacted text is a no-op.
pub fn redact(text: &str) -> String {
    let text = redact_private_keys(text);
    let text = redact_home_paths(&text);
    let text = redact_tokens(&text);
    redact_assignments(&text)
}

/// Replaces PEM private-key blocks, including a truncated block at EOF.
fn redact_private_keys(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_block = false;
    for line in input.split_inclusive('\n') {
        let begins = line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----");
        let ends = line.contains("-----END") && line.contains("PRIVATE KEY-----");

        if in_block {
            if ends {
                in_block = false;
            }
            if line.ends_with('\n') {
                out.push('\n');
            }
            continue;
        }

        if begins {
            out.push_str("[REDACTED PRIVATE KEY]");
            if !ends {
                in_block = true;
            }
            if line.ends_with('\n') {
                out.push('\n');
            }
            continue;
        }

        out.push_str(line);
    }
    out
}

/// Replaces absolute Unix and Windows home-directory prefixes with `[HOME]`.
fn redact_home_paths(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if let Some(prefix_end) = match_home_prefix(input, index) {
            let user_end = consume_user(input, prefix_end);
            if user_end > prefix_end {
                out.push_str(HOME);
                index = user_end;
                continue;
            }
        }
        let ch = input[index..].chars().next().expect("valid char boundary");
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

/// Returns the byte index just after a recognized home prefix, if any.
fn match_home_prefix(input: &str, index: usize) -> Option<usize> {
    let rest = &input[index..];
    for prefix in ["c:\\users\\", "c:/users/"] {
        if rest
            .get(..prefix.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
        {
            return Some(index + prefix.len());
        }
    }
    for prefix in ["/home/", "/Users/"] {
        if rest.starts_with(prefix) && is_path_boundary(input, index) {
            return Some(index + prefix.len());
        }
    }
    None
}

/// A Unix absolute path must start at a boundary, not in the middle of a URL.
fn is_path_boundary(input: &str, index: usize) -> bool {
    if index == 0 {
        return true;
    }
    let previous = input[..index].chars().next_back().unwrap_or(' ');
    previous.is_whitespace() || matches!(previous, '=' | ':' | '"' | '\'' | '(' | '[' | ',' | ';')
}

/// Consumes a user-name segment after a home prefix.
fn consume_user(input: &str, start: usize) -> usize {
    let mut end = start;
    for (offset, ch) in input[start..].char_indices() {
        if ch.is_whitespace()
            || matches!(
                ch,
                '\\' | '/' | '"' | '\'' | ')' | ']' | ',' | ';' | '<' | '>'
            )
        {
            end = start + offset;
            return end;
        }
        end = start + offset + ch.len_utf8();
    }
    end
}

/// Replaces well-known token formats.
fn redact_tokens(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if let Some(end) = match_token(input, index) {
            out.push_str(REDACTED);
            index = end;
            continue;
        }
        let ch = input[index..].chars().next().expect("valid char boundary");
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

/// Matches a credential token starting at `index`, returning its exclusive end.
fn match_token(input: &str, index: usize) -> Option<usize> {
    let rest = &input[index..];

    for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        if rest.starts_with(prefix) {
            let end = consume_while(input, index + prefix.len(), is_ascii_token_char);
            if end - index >= 20 {
                return Some(end);
            }
        }
    }

    if rest.starts_with("github_pat_") {
        let end = consume_while(input, index + "github_pat_".len(), is_ascii_token_char);
        if end - index >= 20 {
            return Some(end);
        }
    }

    for prefix in ["AKIA", "ASIA"] {
        if rest.starts_with(prefix) {
            let end = consume_while(input, index + prefix.len(), |ch| {
                ch.is_ascii_uppercase() || ch.is_ascii_digit()
            });
            if end - index >= 16 {
                return Some(end);
            }
        }
    }

    if rest.starts_with("sk-") {
        let end = consume_while(input, index + 3, |ch| {
            ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'
        });
        if end - index >= 16 {
            return Some(end);
        }
    }

    for prefix in ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"] {
        if rest.starts_with(prefix) {
            let end = consume_while(input, index + prefix.len(), |ch| {
                ch.is_ascii_alphanumeric() || ch == '-'
            });
            if end - index >= 10 {
                return Some(end);
            }
        }
    }

    if rest.starts_with("AIza") {
        let end = consume_while(input, index + 4, |ch| {
            ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'
        });
        if end - index >= 30 {
            return Some(end);
        }
    }

    // JSON Web Tokens: three base64url segments separated by dots.
    if rest.starts_with("eyJ") {
        let end = consume_while(input, index, |ch| {
            ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')
        });
        let token = &input[index..end];
        if token.len() >= 30 && token.matches('.').count() >= 2 {
            return Some(end);
        }
    }

    for prefix in ["Bearer ", "bearer "] {
        if rest.starts_with(prefix) {
            let end = consume_while(input, index + prefix.len(), is_ascii_token_char);
            if end - index - prefix.len() >= 8 {
                return Some(end);
            }
        }
    }

    None
}

/// Bytes that may appear in an opaque credential.
fn is_ascii_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~' | '+' | '/' | '=')
}

/// Consumes characters while `predicate` holds, returning the exclusive end.
fn consume_while(input: &str, start: usize, predicate: impl Fn(char) -> bool) -> usize {
    let mut end = start;
    for (offset, ch) in input[start..].char_indices() {
        if !predicate(ch) {
            break;
        }
        end = start + offset + ch.len_utf8();
    }
    end
}

/// Redacts values of secret-looking assignments on each line.
fn redact_assignments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.split_inclusive('\n') {
        out.push_str(&redact_assignments_in_line(line));
    }
    out
}

/// Redacts every `KEY=value` / `KEY: value` whose key names a secret.
fn redact_assignments_in_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut cursor = 0;
    let mut index = 0;

    while index < line.len() {
        let ch = line[index..].chars().next().expect("valid char boundary");
        if ch != '=' && ch != ':' {
            index += ch.len_utf8();
            continue;
        }

        let key = assignment_key(&line[cursor..index]);
        if !is_secret_key(key) {
            index += ch.len_utf8();
            continue;
        }

        let Some((value_start, value_end, quoted)) = assignment_value(line, index + 1) else {
            index += ch.len_utf8();
            continue;
        };
        let value = &line[value_start..value_end];
        if value.is_empty() || value.starts_with('[') {
            index = value_end.max(index + 1);
            continue;
        }

        out.push_str(&line[cursor..value_start]);
        out.push_str(REDACTED);
        cursor = value_end;
        index = value_end;

        // If the value was quoted, the closing quote is left at `value_end`
        // and will be copied by the next iteration or the final push.
        if quoted {
            index = value_end;
        }
    }

    out.push_str(&line[cursor..]);
    out
}

/// Extracts the key immediately before an assignment delimiter.
fn assignment_key(before: &str) -> &str {
    let before = before.trim_end_matches(|ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                ',' | ';' | '{' | '}' | '(' | ')' | '[' | ']' | '&' | '|'
            )
    });
    let key = before
        .rsplit(|ch: char| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    ',' | ';' | '{' | '}' | '(' | ')' | '[' | ']' | '&' | '|'
                )
        })
        .next()
        .unwrap_or("");
    key.trim_matches(|ch| ch == '"' || ch == '\'' || ch == '`')
}

/// Returns true when a key name indicates a credential.
///
/// Matching is suffix-based so ordinary words such as `token_count` are not
/// mistaken for secrets, while `auth_token`, `client_secret`, and
/// `OPENAI_API_KEY` are.
fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace('-', "_");
    if key.is_empty() {
        return false;
    }
    if key == "apikey" || key == "authorization" {
        return true;
    }
    [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "private_key",
        "access_key",
        "credential",
    ]
    .iter()
    .any(|needle| key == *needle || key.ends_with(&format!("_{needle}")))
}

/// Finds an assignment value after a delimiter.
///
/// Returns `(start, end, quoted)`. A quoted value's bounds exclude the quotes so
/// the quotes are preserved in the output.
fn assignment_value(line: &str, after_delimiter: usize) -> Option<(usize, usize, bool)> {
    let mut start = after_delimiter;
    while start < line.len() {
        let ch = line[start..].chars().next()?;
        if !ch.is_whitespace() {
            break;
        }
        start += ch.len_utf8();
    }
    if start >= line.len() {
        return None;
    }

    let first = line[start..].chars().next()?;
    if first == '"' || first == '\'' {
        let quote = first;
        let content_start = start + first.len_utf8();
        let mut end = content_start;
        for (offset, ch) in line[content_start..].char_indices() {
            if ch == quote {
                return Some((content_start, content_start + offset, true));
            }
            end = content_start + offset + ch.len_utf8();
        }
        return Some((content_start, end, true));
    }

    let mut end = start;
    for (offset, ch) in line[start..].char_indices() {
        if ch.is_whitespace()
            || matches!(
                ch,
                ',' | ';' | '&' | '#' | '"' | '\'' | ')' | ']' | '}' | '|'
            )
        {
            end = start + offset;
            return Some((start, end, false));
        }
        end = start + offset + ch.len_utf8();
    }
    Some((start, end, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_provider_tokens() {
        let input = concat!(
            "github ghp_abcdefghijklmnopqrstuvwxyz0123456789\n",
            "pat github_pat_11AA22BB33CC44DD55EE66FF77GG88HH99II\n",
            "aws AKIAIOSFODNN7EXAMPLE\n",
            "openai sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n",
            "slack xoxb-1234567890-abcdefghijkl\n",
            "google AIzaSyA1234567890abcdefghijklmnopqrstu\n",
        );
        let redacted = redact(input);
        assert!(!redacted.contains("ghp_"));
        assert!(!redacted.contains("github_pat_"));
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!redacted.contains("sk-proj-"));
        assert!(!redacted.contains("xoxb-"));
        assert!(!redacted.contains("AIza"));
        assert!(redacted.matches(REDACTED).count() >= 6, "{redacted}");
    }

    #[test]
    fn redacts_jwts_and_bearer_tokens() {
        let input =
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123";
        let redacted = redact(input);
        assert!(!redacted.contains("eyJhbGci"), "{redacted}");
        assert!(redacted.contains(REDACTED), "{redacted}");
    }

    #[test]
    fn redacts_secret_assignments_and_environment_style_values() {
        let input = concat!(
            "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz\n",
            "client_secret: \"super-secret-value\"\n",
            "aws_secret_access_key = 'abc123'\n",
            "let password = \"hunter2\";\n",
            "token_count = 5\n",
        );
        let redacted = redact(input);
        assert!(!redacted.contains("sk-abcdefghijklmnopqrstuvwxyz"));
        assert!(!redacted.contains("super-secret-value"));
        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains("hunter2"));
        assert!(redacted.contains("token_count = 5"), "{redacted}");
    }

    #[test]
    fn redacts_private_key_blocks() {
        let input = concat!(
            "before\n",
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "MIIEowIBAAKCAQEA\n",
            "-----END RSA PRIVATE KEY-----\n",
            "after\n",
        );
        let redacted = redact(input);
        assert!(!redacted.contains("MIIEowIBAAKCAQEA"));
        assert!(redacted.contains("[REDACTED PRIVATE KEY]"));
        assert!(redacted.contains("before"));
        assert!(redacted.contains("after"));
    }

    #[test]
    fn redacts_unix_and_windows_home_paths() {
        let input = concat!(
            "/home/alice/contracts/src/lib.rs\n",
            "/Users/bob/project\n",
            "C:\\Users\\carol\\project\\src\\lib.rs\n",
            "c:/Users/dave/project\n",
            "https://example.com/home/not-a-home-dir\n",
        );
        let redacted = redact(input);
        assert!(!redacted.contains("alice"));
        assert!(!redacted.contains("bob"));
        assert!(!redacted.contains("carol"));
        assert!(!redacted.contains("dave"));
        assert!(redacted.contains("[HOME]/contracts/src/lib.rs"));
        assert!(
            redacted.contains("https://example.com/home/not-a-home-dir"),
            "{redacted}"
        );
    }

    #[test]
    fn multibyte_text_before_a_path_does_not_panic() {
        let input = "severity: high — /home/alice/project";
        let redacted = redact(input);
        assert!(redacted.contains(HOME), "{redacted}");
        assert!(!redacted.contains("alice"), "{redacted}");
    }

    #[test]
    fn redaction_is_idempotent() {
        let input = "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz /home/alice/x";
        let once = redact(input);
        assert_eq!(redact(&once), once);
    }
}
