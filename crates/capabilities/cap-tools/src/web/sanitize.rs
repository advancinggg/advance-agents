use advance_shared_types::security_validator::TrustLevel;
use advance_shared_types::traits::PromptInjectionHelpers;

const DROP_TAGS: &[&str] = &[
    "script", "style", "iframe", "object", "embed", "noscript", "template",
];

pub fn sanitize_web_text(input: &str, helpers: Option<&dyn PromptInjectionHelpers>) -> String {
    // Decode first so `&lt;script&gt;` cannot survive tag-strip.
    let mut s = decode_entities(input);
    s = strip_comments(&s);
    s = drop_hidden_elements(&s);
    s = strip_tags(&s);
    s = strip_hidden_attrs(&s);
    s = strip_event_handlers(&s);
    s = drop_bad_schemes(&s);
    s = collapse_ws(&s);
    if let Some(h) = helpers {
        let flags = h.flag_injection_patterns(&s);
        if !flags.is_empty() {
            s = h.wrap_with_boundary(&s, "web", TrustLevel::Untrusted);
        }
    }
    s
}

fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        rest = rest.get(start + 4..).unwrap_or("");
        if let Some(end) = rest.find("-->") {
            rest = rest.get(end + 3..).unwrap_or("");
        } else {
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

fn strip_tags(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = s.to_string();
    for tag in DROP_TAGS {
        loop {
            let open = format!("<{tag}");
            let close = format!("</{tag}>");
            let l = out.to_ascii_lowercase();
            let Some(start) = find_tag_token(&l, &open) else {
                break;
            };
            let after = out.get(start..).unwrap_or("");
            let after_l = after.to_ascii_lowercase();
            let close_prefix = format!("</{tag}");
            let end = find_tag_token(&after_l, &close_prefix)
                .and_then(|i| after_l[i..].find('>').map(|j| start + i + j + 1))
                .or_else(|| find_tag_token(&after_l, &close).map(|i| start + i + close.len()))
                .unwrap_or(out.len());
            out.replace_range(start..end.min(out.len()), " ");
        }
    }
    // Strip remaining tags.
    let mut result = String::with_capacity(out.len());
    let mut in_tag = false;
    for c in out.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if !in_tag => result.push(c),
            _ => {}
        }
    }
    let _ = lower;
    result
}

fn drop_hidden_elements(s: &str) -> String {
    let mut out = s.to_string();
    loop {
        let lower = out.to_ascii_lowercase();
        let Some(idx) = find_hidden_marker(&html_ws_to_space(&lower)) else {
            break;
        };
        let start = out[..idx].rfind('<').unwrap_or(idx);
        let end = matching_element_end(&out, start);
        if end <= start {
            break;
        }
        out.replace_range(start..end.min(out.len()), " ");
    }
    out
}

fn find_hidden_marker(lower: &str) -> Option<usize> {
    let literals = [
        "aria-hidden",
        " hidden=",
        " hidden>",
        " hidden/>",
        " hidden >",
        " hidden\n",
        " hidden\t",
        " hidden\r",
        " hidden\u{0c}",
        " hidden ",
        "hidden>",
        "hidden/>",
        "/hidden",
        " hidden/",
        "class=\"hidden\"",
        "class='hidden'",
        "class=hidden",
        "class=\"hidden ",
        "class='hidden ",
        " hidden\"",
        " hidden'",
        "display=\"none\"",
        "display='none'",
        "display=none",
    ];
    let lit = literals
        .iter()
        .filter_map(|m| lower.find(m).map(|i| (i, *m)))
        .min_by_key(|(i, _)| *i)
        .map(|(i, _)| i);
    let css = find_css_none_or_hidden(lower);
    match (lit, css) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn find_css_none_or_hidden(lower: &str) -> Option<usize> {
    let bytes = lower.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &lower[i..];
        let (kw, val) = if rest.starts_with("display") {
            ("display", "none")
        } else if rest.starts_with("visibility") {
            ("visibility", "hidden")
        } else {
            i += 1;
            continue;
        };
        let mut j = skip_ws_and_comments(bytes, i + kw.len());
        if j < bytes.len() && bytes[j] == b':' {
            j = skip_ws_and_comments(bytes, j + 1);
            if lower[j..].starts_with(val) {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn matching_element_end(s: &str, start: usize) -> usize {
    let lower = s.to_ascii_lowercase();
    let after_lt = start + 1;
    let name_end = s[after_lt..]
        .char_indices()
        .find(|(_, c)| !is_tag_name_char(*c))
        .map(|(i, _)| after_lt + i)
        .unwrap_or(s.len());
    let name = lower[after_lt..name_end].to_string();
    if name.is_empty() {
        return s[start..]
            .find('>')
            .map(|i| start + i + 1)
            .unwrap_or(s.len());
    }
    let open = format!("<{name}");
    let close = format!("</{name}");
    let mut i = s[start..]
        .find('>')
        .map(|x| start + x + 1)
        .unwrap_or(s.len());
    let mut depth = 1i32;
    while i < s.len() && depth > 0 {
        let rest = &lower[i..];
        let next_open = find_tag_token(rest, &open);
        let next_close = find_tag_token(rest, &close);
        match (next_open, next_close) {
            (Some(o), Some(c)) if o < c => {
                depth += 1;
                i += o + open.len();
            }
            (Some(o), None) => {
                depth += 1;
                i += o + open.len();
            }
            (_, Some(c)) => {
                depth -= 1;
                let close_at = i + c;
                i = close_at + close.len();
                if depth == 0 {
                    return lower[close_at..]
                        .find('>')
                        .map(|j| close_at + j + 1)
                        .unwrap_or(s.len());
                }
            }
            _ => return s.len(),
        }
    }
    s.len()
}

fn html_ws_to_space(s: &str) -> String {
    s.chars()
        .map(|c| {
            if matches!(c, '\t' | '\n' | '\r' | '\u{0c}') {
                ' '
            } else {
                c
            }
        })
        .collect()
}

fn is_tag_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')
}

fn find_tag_token(hay: &str, token: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = hay[from..].find(token) {
        let at = from + rel;
        let after = hay[at + token.len()..].chars().next();
        if after.is_none_or(|c| !is_tag_name_char(c)) {
            return Some(at);
        }
        from = at + token.len();
    }
    None
}

fn skip_ws_and_comments(bytes: &[u8], mut j: usize) -> usize {
    loop {
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j + 1 < bytes.len() && bytes[j] == b'/' && bytes[j + 1] == b'*' {
            if let Some(end) = bytes[j + 2..].windows(2).position(|w| w == b"*/") {
                j = j + 2 + end + 2;
                continue;
            }
            return bytes.len();
        }
        return j;
    }
}

fn strip_hidden_attrs(s: &str) -> String {
    let l = s.to_ascii_lowercase();
    if l.contains("display:none") || l.contains("visibility:hidden") || l.contains("aria-hidden") {
        // Drop the whole string segments that look hidden; remaining tag-strip already ran.
        s.replace("display:none", " ")
            .replace("visibility:hidden", " ")
            .replace("aria-hidden", " ")
    } else {
        s.to_string()
    }
}

fn strip_event_handlers(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for word in s.split_whitespace() {
        let lw = word.to_ascii_lowercase();
        if lw.starts_with("on") && lw.contains('=') {
            continue;
        }
        out.push_str(word);
        out.push(' ');
    }
    out
}

fn drop_bad_schemes(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut prev: Option<char> = None;
    while i < s.len() {
        let rest = &lower[i..];
        let scheme_len = if rest.starts_with("javascript:") {
            Some("javascript:".len())
        } else if rest.starts_with("vbscript:") {
            Some("vbscript:".len())
        } else if rest.starts_with("data:") && is_scheme_boundary(prev) {
            Some("data:".len())
        } else {
            None
        };
        if let Some(n) = scheme_len {
            out.push(' ');
            i += n;
            prev = Some(' ');
            continue;
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
        prev = Some(ch);
    }
    out
}

fn is_scheme_boundary(prev: Option<char>) -> bool {
    match prev {
        None => true,
        Some(c) => c.is_whitespace() || matches!(c, '=' | '"' | '\'' | '(' | '<' | ':'),
    }
}

fn decode_entities(s: &str) -> String {
    let mut out = s
        .replace("&lt;", "<")
        .replace("&LT;", "<")
        .replace("&gt;", ">")
        .replace("&GT;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
        .replace("&colon;", ":")
        .replace("&COLON;", ":");
    out = decode_numeric_entities(&out);
    out
}

fn decode_numeric_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("&#") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let hex = after.starts_with('x') || after.starts_with('X');
        let digits = if hex { &after[1..] } else { after };
        let end = digits.find(';').unwrap_or(0);
        let num = &digits[..end];
        let parsed = if hex {
            u32::from_str_radix(num, 16).ok()
        } else {
            num.parse::<u32>().ok()
        };
        if let Some(cp) = parsed.and_then(char::from_u32) {
            out.push(cp);
            rest = &digits[end + 1..];
        } else {
            out.push_str("&#");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            prev_space = false;
            out.push(c);
        }
    }
    out.trim().to_string()
}
