//! A parser for micron, the page markup language served by NomadNet nodes
//! (`.mu` pages). Sans-IO and dependency-free so it runs under plain host
//! `cargo test` like the other protocol crates.
//!
//! The output model is a flat list of styled LINES, because the Precursor
//! renderer draws one TextView per line and a TextView has exactly one
//! GlyphStyle: intra-line styling cannot be rendered, so it is flattened
//! (a line takes the bold state in effect at its first visible character).
//! On the 336x536 1-bit display, colors, italic, underline and section
//! indentation are consumed and dropped. Links become their own selectable
//! lines. Malformed input never panics; unknown tags are skipped.

/// A parsed page.
#[derive(Debug, Default)]
pub struct Document {
    /// From a `#!c=<seconds>` header line, if present.
    pub cache_secs: Option<u32>,
    pub lines: Vec<Line>,
    pub links: Vec<Link>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub text: String,
    pub style: Style,
    pub align: Align,
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Style {
    Regular,
    Bold,
    Mono,
    /// Heading depth 1..=3.
    Heading(u8),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Align {
    Left,
    Center,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    Text,
    /// Rendered as a horizontal rule; `text` is empty.
    Divider,
    /// A selectable link line; the value indexes `Document::links`.
    Link(u16),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    pub label: String,
    pub url: String,
    /// URL variables from the link's trailing component(s): `` `[label`url`g=mirrors|s=x] ``
    /// → `[("g","mirrors"),("s","x")]`. NomadNet sends these in the request
    /// data dict as `{"var_<name>": value}`.
    pub fields: Vec<(String, String)>,
}

/// Where a link URL points. NomadNet conventions:
/// `:/page/foo.mu` (same node), `<32hex>:/page/foo.mu` (another node),
/// bare `<32hex>` (another node's index page), `#anchor` (in-page),
/// `lxmf@<32hex>` (a messaging address).
#[derive(Debug, Clone, PartialEq)]
pub enum LinkTarget {
    SameNode(String),
    OtherNode([u8; 16], String),
    NodeIndex([u8; 16]),
    Lxmf([u8; 16]),
    Anchor,
    Unsupported,
}

/// Hard caps so a hostile page can't balloon memory on the device.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_LINES: usize = 2000;

/// Persistent inline-formatting state; micron state spans lines until reset.
struct ScanState {
    bold: bool,
    align: Align,
    literal: bool,
}

pub fn parse(src: &str) -> Document {
    let src = truncate_utf8(src, MAX_INPUT_BYTES);
    let mut doc = Document::default();
    let mut st = ScanState { bold: false, align: Align::Left, literal: false };

    for line in src.lines() {
        if doc.lines.len() >= MAX_LINES {
            break;
        }

        // The literal toggle is a line consisting of exactly `=, in any mode.
        if line.trim() == "`=" {
            st.literal = !st.literal;
            continue;
        }
        if st.literal {
            // Inside a literal block \`= emits a literal `= (upstream rule);
            // everything else passes through verbatim in mono.
            let text = if line.trim() == "\\`=" { "`=".to_string() } else { line.to_string() };
            push_line(&mut doc, text, Style::Mono, Align::Left, Kind::Text);
            continue;
        }

        if let Some(rest) = line.strip_prefix("#!c=") {
            if doc.cache_secs.is_none() {
                doc.cache_secs = rest.trim().parse::<u32>().ok();
            }
            continue;
        }
        if line.starts_with('#') {
            continue; // comment
        }
        // Table begin/end markers: we don't render tables; the buffered lines
        // between markers still parse as ordinary text.
        if line.starts_with("`t") {
            continue;
        }
        if line.starts_with('-') {
            push_line(&mut doc, String::new(), Style::Regular, st.align, Kind::Divider);
            continue;
        }

        // Headings: 1-3 leading '>'. A leading '<' resets section depth,
        // which we don't track — strip it and parse the remainder.
        let mut body = line;
        let mut heading = 0u8;
        while body.starts_with('>') && heading < 3 {
            heading += 1;
            body = &body[1..];
        }
        if heading == 0 {
            body = body.strip_prefix('<').unwrap_or(body);
        }

        if body.is_empty() && heading == 0 {
            // Preserve blank source lines as paragraph spacing.
            push_line(&mut doc, String::new(), Style::Regular, st.align, Kind::Text);
            continue;
        }

        scan_inline(body, heading, &mut st, &mut doc);
    }
    doc
}

/// Scan one line's body: consume inline tags, flush text segments and link
/// lines into the document. `heading` > 0 forces Heading style on text and
/// suppresses link extraction (links in headings keep their label inline).
fn scan_inline(body: &str, heading: u8, st: &mut ScanState, doc: &mut Document) {
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0usize;
    let mut seg = String::new();
    // Style/alignment a flushed segment uses: captured when its first
    // visible character lands, so tags ahead of the text take effect.
    let mut seg_bold: Option<bool> = None;
    let mut seg_align: Option<Align> = None;
    let mut emitted = false;

    macro_rules! push_seg_char {
        ($c:expr) => {{
            if seg.is_empty() {
                seg_bold = Some(st.bold);
                seg_align = Some(st.align);
            }
            seg.push($c);
        }};
    }
    macro_rules! flush_seg {
        () => {{
            if !seg.trim().is_empty() {
                let style = if heading > 0 {
                    Style::Heading(heading)
                } else if seg_bold.unwrap_or(st.bold) {
                    Style::Bold
                } else {
                    Style::Regular
                };
                push_line(
                    doc,
                    core::mem::take(&mut seg),
                    style,
                    seg_align.unwrap_or(st.align),
                    Kind::Text,
                );
                emitted = true;
            } else {
                seg.clear();
            }
            // seg is empty now; the next push_seg_char recaptures state.
        }};
    }

    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' => {
                // Backslash escapes the next character.
                if i + 1 < chars.len() {
                    push_seg_char!(chars[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            '`' => {
                i += 1;
                let t = if i < chars.len() { chars[i] } else { '\u{0}' };
                match t {
                    '`' => {
                        // Reset all formatting.
                        st.bold = false;
                        st.align = Align::Left;
                        i += 1;
                    }
                    '!' => {
                        st.bold = !st.bold;
                        i += 1;
                    }
                    '*' | '_' => i += 1, // italic/underline: dropped
                    'F' | 'B' => {
                        // Color: `F/`B + 3 chars (hex or gNN), or T + 6 for
                        // truecolor. Dropped on a 1-bit display.
                        i += 1;
                        let n = if i < chars.len() && chars[i] == 'T' { 7 } else { 3 };
                        i = (i + n).min(chars.len());
                    }
                    'f' | 'b' => i += 1, // color reset: dropped
                    'c' => {
                        st.align = Align::Center;
                        i += 1;
                    }
                    'r' => {
                        st.align = Align::Right;
                        i += 1;
                    }
                    'l' | 'a' => {
                        st.align = Align::Left;
                        i += 1;
                    }
                    '<' => {
                        // Input field `<[flags]|name`value>: phase 1 renders a
                        // placeholder. Consume through the closing '>'.
                        i += 1;
                        while i < chars.len() && chars[i] != '>' {
                            i += 1;
                        }
                        i = (i + 1).min(chars.len());
                        for ch in "[____]".chars() {
                            push_seg_char!(ch);
                        }
                    }
                    '{' => {
                        // Partial/dynamic embed `{url`refresh`fields}: dropped.
                        i += 1;
                        while i < chars.len() && chars[i] != '}' {
                            i += 1;
                        }
                        i = (i + 1).min(chars.len());
                    }
                    '[' => {
                        // A link: `[label`URL] / `[URL] (`fields ignored).
                        // NOTE the leading backtick — real micron links are
                        // backtick-bracket (a bare [ is literal text), which a
                        // live rngit page demonstrated after our own test pages
                        // (wrongly bare-bracketed) hid it.
                        match try_parse_link(&chars[i..]) {
                            Some((link, consumed)) => {
                                if heading > 0 {
                                    // No selectable lines inside headings; keep the label.
                                    for ch in link.label.chars() {
                                        push_seg_char!(ch);
                                    }
                                } else {
                                    flush_seg!();
                                    if doc.links.len() < u16::MAX as usize {
                                        let id = doc.links.len() as u16;
                                        let text = format!("\u{00bb} {}", link.label);
                                        doc.links.push(link);
                                        push_line(doc, text, Style::Regular, st.align, Kind::Link(id));
                                        emitted = true;
                                    }
                                }
                                i += consumed;
                            }
                            // Unclosed on this line: keep it visible as text.
                            None => {
                                push_seg_char!('[');
                                i += 1;
                            }
                        }
                    }
                    '=' => i += 1, // mid-line literal toggle: only line-form supported
                    '\u{0}' => {}  // trailing lone backtick: dropped
                    _ => i += 1,   // unknown tag: skip it
                }
            }
            _ => {
                push_seg_char!(c);
                i += 1;
            }
        }
    }
    flush_seg!();
    if !emitted && heading == 0 {
        // The line was all tags (e.g. a bare `c): nothing to show.
    }
}

/// Parse the bracket body of a `` `[...] `` link, starting at `chars[0] == '['`
/// (the backtick is already consumed). Returns the link and how many chars
/// (including the brackets) were consumed. The backtick marker makes the
/// single-component `` `[URL] `` form unambiguous, so any non-empty body is a
/// link; the URL may still resolve as Unsupported at follow time.
fn try_parse_link(chars: &[char]) -> Option<(Link, usize)> {
    let close = chars.iter().position(|&c| c == ']')?;
    if close < 2 {
        return None; // `[] — nothing useful
    }
    let inner: String = chars[1..close].iter().collect();
    // label`URL`vars — the trailing component(s) are |-separated k=v URL
    // variables the node receives as request data (mirrors NomadNet's
    // retrieve_url: each "k=v" → request_data["var_k"] = "v").
    let mut parts = inner.split('`');
    let first = parts.next().unwrap_or("");
    let url = parts.next().unwrap_or(first); // `[URL] form: label is the URL
    if url.is_empty() {
        return None;
    }
    let mut fields = Vec::new();
    for varstr in parts {
        for e in varstr.split('|') {
            if let Some((k, v)) = e.split_once('=') {
                if !k.is_empty() {
                    fields.push((k.to_string(), v.to_string()));
                }
            }
        }
    }
    Some((
        Link { label: first.to_string(), url: url.to_string(), fields },
        close + 1,
    ))
}

/// Resolve a link URL into a navigation target.
pub fn resolve_link(url: &str) -> LinkTarget {
    let url = url.trim();
    if url.is_empty() {
        return LinkTarget::Unsupported;
    }
    if url.starts_with('#') {
        return LinkTarget::Anchor;
    }
    if let Some((scheme, rest)) = url.split_once('@') {
        // lxmf@<hash> style address links; other schemes unsupported.
        if scheme.eq_ignore_ascii_case("lxmf") {
            if let Some(h) = parse_hash(rest.split(':').next().unwrap_or("")) {
                return LinkTarget::Lxmf(h);
            }
        }
        return LinkTarget::Unsupported;
    }
    match url.split_once(':') {
        Some(("", path)) => LinkTarget::SameNode(path.to_string()),
        Some((node, path)) => match parse_hash(node) {
            Some(h) if !path.is_empty() => LinkTarget::OtherNode(h, path.to_string()),
            Some(h) => LinkTarget::NodeIndex(h),
            None => LinkTarget::Unsupported,
        },
        None => {
            if let Some(h) = parse_hash(url) {
                LinkTarget::NodeIndex(h)
            } else if url.starts_with('/') {
                LinkTarget::SameNode(url.to_string())
            } else {
                LinkTarget::Unsupported
            }
        }
    }
}

fn parse_hash(s: &str) -> Option<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn push_line(doc: &mut Document, text: String, style: Style, align: Align, kind: Kind) {
    if doc.lines.len() < MAX_LINES {
        doc.lines.push(Line { text, style, align, kind });
    }
}

fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(doc: &Document) -> Vec<&str> {
        doc.lines.iter().map(|l| l.text.as_str()).collect()
    }

    #[test]
    fn headings_dividers_and_text() {
        let doc = parse(">Welcome\n>>Sub\n>>>Deep\nplain text\n-\n-=\n");
        assert_eq!(doc.lines[0].style, Style::Heading(1));
        assert_eq!(doc.lines[0].text, "Welcome");
        assert_eq!(doc.lines[1].style, Style::Heading(2));
        assert_eq!(doc.lines[2].style, Style::Heading(3));
        assert_eq!(doc.lines[3].style, Style::Regular);
        assert_eq!(doc.lines[4].kind, Kind::Divider);
        assert_eq!(doc.lines[5].kind, Kind::Divider);
    }

    #[test]
    fn comments_and_cache_header() {
        let doc = parse("#!c=600\n# a comment\nvisible\n");
        assert_eq!(doc.cache_secs, Some(600));
        assert_eq!(texts(&doc), vec!["visible"]);
    }

    #[test]
    fn literal_mode_is_verbatim_mono() {
        let doc = parse("`=\n># not a heading or comment\n`!still literal\n\\`=\n`=\nafter\n");
        assert_eq!(doc.lines[0].text, "># not a heading or comment");
        assert_eq!(doc.lines[0].style, Style::Mono);
        assert_eq!(doc.lines[1].text, "`!still literal");
        assert_eq!(doc.lines[2].text, "`=");
        assert_eq!(doc.lines[3].text, "after");
        assert_eq!(doc.lines[3].style, Style::Regular);
    }

    #[test]
    fn bold_at_line_start_styles_the_line() {
        let doc = parse("`!bold line\nstill bold\n`!plain again\n");
        assert_eq!(doc.lines[0].style, Style::Bold);
        assert_eq!(doc.lines[0].text, "bold line");
        // Bold state persists across lines until toggled off.
        assert_eq!(doc.lines[1].style, Style::Bold);
        assert_eq!(doc.lines[2].style, Style::Regular);
    }

    #[test]
    fn colors_italic_underline_dropped() {
        let doc = parse("`F0f0green`f `*ital`* `_under`_ done\n`Bf00on red`b\n");
        assert_eq!(doc.lines[0].text, "green ital under done");
        assert_eq!(doc.lines[1].text, "on red");
        // Truecolor variant consumes 7.
        let doc = parse("`FT00ff00x`f y\n");
        assert_eq!(doc.lines[0].text, "x y");
    }

    #[test]
    fn alignment_applies_per_line() {
        let doc = parse("`ccentered\n`rright\n`lleft\n`a default\n");
        assert_eq!(doc.lines[0].align, Align::Center);
        assert_eq!(doc.lines[1].align, Align::Right);
        assert_eq!(doc.lines[2].align, Align::Left);
        assert_eq!(doc.lines[3].align, Align::Left);
    }

    #[test]
    fn reset_clears_bold_and_align() {
        let doc = parse("`!`cstyled\n``plain\n");
        assert_eq!(doc.lines[0].style, Style::Bold);
        assert_eq!(doc.lines[0].align, Align::Center);
        assert_eq!(doc.lines[1].style, Style::Regular);
        assert_eq!(doc.lines[1].align, Align::Left);
    }

    #[test]
    fn links_become_their_own_lines() {
        let doc = parse("Before `[Home`:/page/index.mu] after\n");
        assert_eq!(doc.lines.len(), 3);
        assert_eq!(doc.lines[0].text, "Before ");
        assert_eq!(doc.lines[1].kind, Kind::Link(0));
        assert_eq!(doc.lines[1].text, "\u{00bb} Home");
        assert_eq!(doc.lines[2].text, " after");
        assert_eq!(
            doc.links[0],
            Link { label: "Home".into(), url: ":/page/index.mu".into(), fields: vec![] }
        );
    }

    #[test]
    fn bare_url_link_and_extra_fields() {
        let doc = parse("`[:/page/a.mu]\n`[Send`:/page/b.mu`field_x|1]\n");
        assert_eq!(doc.links[0].label, ":/page/a.mu");
        assert_eq!(doc.links[0].url, ":/page/a.mu");
        assert_eq!(doc.links[1].label, "Send");
        assert_eq!(doc.links[1].url, ":/page/b.mu"); // form fields ignored
    }

    #[test]
    fn real_rngit_page_links_extract() {
        // Cut down from a live rngit index page — the page that exposed the
        // bare-vs-backtick bracket bug (we extracted 0 links from it).
        let doc = parse(
            "#!c=0\n#!bg=1a1d1f\n>Aleph Git\n\
             `!`[Node`:/page/index.mu]`! /\n\
             `!`[  • mirrors`:/page/group.mu`g=mirrors]`! (14 repositories)\n\
             `a`F666`[Served by rngit 1.3.5`:/page/index.mu] - Generated in 0s`f\n",
        );
        assert_eq!(doc.links.len(), 3);
        assert_eq!(
            doc.links[0],
            Link { label: "Node".into(), url: ":/page/index.mu".into(), fields: vec![] }
        );
        assert_eq!(doc.links[1].label, "  • mirrors");
        assert_eq!(doc.links[1].url, ":/page/group.mu");
        assert_eq!(doc.links[1].fields, vec![("g".to_string(), "mirrors".to_string())]);
        assert_eq!(doc.links[2].label, "Served by rngit 1.3.5");
        let link_lines = doc.lines.iter().filter(|l| matches!(l.kind, Kind::Link(_))).count();
        assert_eq!(link_lines, 3);
    }

    #[test]
    fn bare_brackets_are_literal() {
        // Real micron links are backtick-bracket; a plain [ is just text.
        let doc = parse("array[0] = 1\n[Home`:/page/index.mu]\nlone [ bracket\n`[unclosed\n");
        assert_eq!(doc.lines[0].text, "array[0] = 1");
        // The stray ` reads as an unknown tag and eats the ':' — no link either way.
        assert_eq!(doc.lines[1].text, "[Home/page/index.mu]");
        assert_eq!(doc.lines[2].text, "lone [ bracket");
        assert_eq!(doc.lines[3].text, "[unclosed");
        assert!(doc.links.is_empty());
    }

    #[test]
    fn fields_render_placeholder_and_dont_crash() {
        let doc = parse("Name: `<24|username`admin>\n`<!|pass`>\n");
        assert_eq!(doc.lines[0].text, "Name: [____]");
        assert_eq!(doc.lines[1].text, "[____]");
    }

    #[test]
    fn resolve_link_forms() {
        let h = "00112233445566778899aabbccddeeff";
        let mut hb = [0u8; 16];
        for i in 0..16 {
            hb[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        assert_eq!(resolve_link(":/page/x.mu"), LinkTarget::SameNode("/page/x.mu".into()));
        assert_eq!(resolve_link("/page/x.mu"), LinkTarget::SameNode("/page/x.mu".into()));
        assert_eq!(
            resolve_link(&format!("{h}:/page/x.mu")),
            LinkTarget::OtherNode(hb, "/page/x.mu".into())
        );
        assert_eq!(resolve_link(h), LinkTarget::NodeIndex(hb));
        assert_eq!(resolve_link("#top"), LinkTarget::Anchor);
        assert_eq!(resolve_link(&format!("lxmf@{h}")), LinkTarget::Lxmf(hb));
        assert_eq!(resolve_link("https://example.com"), LinkTarget::Unsupported);
        assert_eq!(resolve_link("nope"), LinkTarget::Unsupported);
        assert_eq!(resolve_link(""), LinkTarget::Unsupported);
    }

    #[test]
    fn escapes_and_stray_backticks() {
        let doc = parse("a \\`! literal tag\nprice 100`\n\\[not a link]\n");
        assert_eq!(doc.lines[0].text, "a `! literal tag");
        assert_eq!(doc.lines[1].text, "price 100");
        assert_eq!(doc.lines[2].text, "[not a link]");
        assert!(doc.links.is_empty());
    }

    #[test]
    fn crlf_blank_lines_and_depth_reset() {
        let doc = parse("one\r\n\r\n<two\r\n");
        assert_eq!(texts(&doc), vec!["one", "", "two"]);
    }

    #[test]
    fn caps_bound_hostile_input() {
        let big = "x\n".repeat(MAX_LINES * 2);
        let doc = parse(&big);
        assert_eq!(doc.lines.len(), MAX_LINES);
        let long = "y".repeat(MAX_INPUT_BYTES * 2);
        let doc = parse(&long);
        assert_eq!(doc.lines.len(), 1);
        assert!(doc.lines[0].text.len() <= MAX_INPUT_BYTES);
    }

    #[test]
    fn tables_and_partials_degrade() {
        let doc = parse("`tl40\ncell text\n`t\n`{:/page/p.mu`30}embedded\n");
        // Marker lines dropped, buffered line kept as text, partial dropped.
        assert_eq!(texts(&doc), vec!["cell text", "embedded"]);
    }
}
