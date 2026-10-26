//! A minimal line-level reader and editor of block-style YAML, the kind a
//! hand-kept site file is written in. It finds a key by its path through
//! block mappings, and one level into a one-line flow mapping (`txpower:
//! {"5": 26}`), reads its scalar, and replaces only that value's text or adds
//! the key, so every other byte of the file stays as it was, comments
//! included: an edit is a diff of the lines it means to change. It is not a
//! YAML parser: what it does not understand on the path it is asked for (a
//! tab, a quote left open, a value spanning lines) is an error, never a guess.

use std::fmt;

/// Why a path could not be read or edited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn error<T>(line: usize, why: impl fmt::Display) -> Result<T, Error> {
    Err(Error(format!("line {}: {why}", line + 1)))
}

/// A byte range of a line.
type Span = (usize, usize);

/// One `key: value` line: its key unquoted, where its value's text is (empty
/// for a key whose mapping follows on the lines below), and where its
/// comment starts, if it has one.
#[derive(Debug)]
struct Entry {
    indent: usize,
    key: String,
    value: Span,
    comment: Option<usize>,
}

/// What a line is to the structure: nothing (blank or a comment), a mapping
/// entry, or other content (a sequence item, a document marker).
enum Kind {
    Blank,
    Entry(Entry),
    Other(usize),
}

/// The end of a quoted string that starts at `start` (a `"` or `'`).
fn close_quote(s: &str, start: usize) -> Option<usize> {
    let b = s.as_bytes();
    let q = b[start];
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'\\' if q == b'"' => i += 1,
            c if c == q && q == b'\'' && b.get(i + 1) == Some(&b'\'') => i += 1,
            c if c == q => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Where the comment of `s` (from `from` on) starts: a `#` after a space
/// and outside quotes.
fn comment_start(s: &str, from: usize) -> Result<Option<usize>, &'static str> {
    let b = s.as_bytes();
    let mut i = from;
    while i < b.len() {
        match b[i] {
            b'"' | b'\'' => i = close_quote(s, i).ok_or("a quote is not closed")?,
            b'#' if i == from || b[i - 1] == b' ' => return Ok(Some(i)),
            _ => {}
        }
        i += 1;
    }
    Ok(None)
}

fn classify(n: usize, line: &str) -> Result<Kind, Error> {
    let body = line.trim_start_matches(' ');
    let indent = line.len() - body.len();
    if body.starts_with('\t') {
        return error(n, "a tab indents it");
    }
    if body.trim().is_empty() || body.starts_with('#') {
        return Ok(Kind::Blank);
    }
    if body.starts_with("- ") || body == "-" || body.starts_with("---") || body == "..." {
        return Ok(Kind::Other(indent));
    }
    let (key, colon) = if body.starts_with(['"', '\'']) {
        let Some(end) = close_quote(body, 0) else {
            return error(n, "a quote is not closed");
        };
        if body.as_bytes().get(end + 1) != Some(&b':') {
            return Ok(Kind::Other(indent));
        }
        (unquote(&body[..=end]), end + 1)
    } else {
        let colon = body
            .match_indices(':')
            .map(|(i, _)| i)
            .find(|&i| matches!(body.as_bytes().get(i + 1), None | Some(b' ')));
        match colon {
            Some(c) if !body[..c].contains(" #") => (body[..c].to_owned(), c),
            _ => return Ok(Kind::Other(indent)),
        }
    };
    let after = indent + colon + 1;
    let comment = comment_start(line, after).or_else(|why| error(n, why))?;
    let end = comment.unwrap_or(line.len());
    let text = &line[after..end];
    let start = after + (text.len() - text.trim_start().len());
    let stop = start + line[start..end].trim_end().len();
    Ok(Kind::Entry(Entry {
        indent,
        key,
        value: (start, stop.max(start)),
        comment,
    }))
}

/// The scalar a YAML spelling means: quotes taken off, escapes undone (the
/// two the site file can hold, `\"` and `\\`, and `''`).
pub fn unquote(raw: &str) -> String {
    let raw = raw.trim();
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        let inner = &raw[1..raw.len() - 1];
        return inner.replace("\\\"", "\"").replace("\\\\", "\\");
    }
    if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        return raw[1..raw.len() - 1].replace("''", "'");
    }
    raw.to_owned()
}

/// A key as YAML must spell it to keep it a string: quoted when it would
/// otherwise read as a number or holds anything but letters, digits, `_`
/// and `-`.
fn key_text(key: &str) -> String {
    let plain = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c))
        && !key.chars().all(|c| c.is_ascii_digit());
    if plain { key.to_owned() } else { quoted(key) }
}

/// A string as a double-quoted YAML scalar.
pub fn quoted(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The items of a one-line flow mapping `{k: v, …}` at `at` of `line`: each
/// key unquoted and where its value is.
fn flow_items(n: usize, line: &str, at: Span) -> Result<Vec<(String, Span)>, Error> {
    let text = &line[at.0..at.1];
    if !(text.starts_with('{') && text.ends_with('}')) {
        return error(n, "not a mapping");
    }
    let (open, close) = (at.0 + 1, at.1 - 1);
    let b = line.as_bytes();
    let mut items = Vec::new();
    let mut start = open;
    let mut i = open;
    while i <= close {
        match b[i] {
            b'"' | b'\'' => {
                i = match close_quote(line, i) {
                    Some(e) if e < close => e,
                    _ => return error(n, "a quote is not closed"),
                }
            }
            b'{' | b'[' => return error(n, "a nested collection in a flow mapping"),
            b',' | b'}' if i == close || b[i] == b',' => {
                let item = &line[start..i];
                if !item.trim().is_empty() {
                    let lead = item.len() - item.trim_start().len();
                    let item_start = start + lead;
                    let body = item.trim();
                    let colon = if body.starts_with(['"', '\'']) {
                        close_quote(body, 0).map(|e| e + 1)
                    } else {
                        body.find(':')
                    };
                    let Some(c) = colon.filter(|&c| body.as_bytes().get(c) == Some(&b':')) else {
                        return error(n, "a flow mapping item is not key: value");
                    };
                    let v = &body[c + 1..];
                    let vs = item_start + c + 1 + (v.len() - v.trim_start().len());
                    items.push((unquote(&body[..c]), (vs, item_start + body.len())));
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    Ok(items)
}

/// Where a path leads.
enum Found {
    /// The key is on this line.
    Line(usize),
    /// The key is in the flow mapping on this line, its value there.
    Flow(usize, Span),
    /// The key is not there; `rest` of the path is missing below `at`.
    Missing { at: Parent, rest: usize },
}

/// Where missing keys would go.
enum Parent {
    /// The block mapping on lines `from..to` (the whole file at the root),
    /// its keys at `indent`.
    Block {
        from: usize,
        to: usize,
        indent: usize,
    },
    /// The flow mapping on this line, at this value.
    Flow(usize, Span),
}

/// A YAML document as lines, edited in place.
pub struct Doc {
    lines: Vec<String>,
    kinds: Vec<Kind>,
}

impl Doc {
    pub fn parse(text: &str) -> Result<Doc, Error> {
        let lines: Vec<String> = text.split('\n').map(str::to_owned).collect();
        let kinds = lines
            .iter()
            .enumerate()
            .map(|(n, l)| classify(n, l))
            .collect::<Result<_, _>>()?;
        Ok(Doc { lines, kinds })
    }

    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    fn reparse(&mut self) -> Result<(), Error> {
        *self = Doc::parse(&self.text())?;
        Ok(())
    }

    fn entry(&self, i: usize) -> &Entry {
        match &self.kinds[i] {
            Kind::Entry(e) => e,
            _ => unreachable!("found lines are entries"),
        }
    }

    fn indent(&self, i: usize) -> Option<usize> {
        match &self.kinds[i] {
            Kind::Blank => None,
            Kind::Entry(e) => Some(e.indent),
            Kind::Other(indent) => Some(*indent),
        }
    }

    /// The lines below the entry on line `i` that are its mapping's, and the
    /// indent of their keys (`None` when it has none).
    fn block_of(&self, i: usize) -> (usize, usize, Option<usize>) {
        let own = self.entry(i).indent;
        let mut end = i + 1;
        let mut last = i + 1;
        let mut inner = None;
        while end < self.lines.len() {
            match self.indent(end) {
                Some(ind) if ind <= own => break,
                Some(ind) => {
                    inner.get_or_insert(ind);
                    last = end + 1;
                }
                None => {}
            }
            end += 1;
        }
        (i + 1, last, inner)
    }

    fn find(&self, path: &[&str]) -> Result<Found, Error> {
        let mut from = 0;
        let mut to = self.lines.len();
        let mut indent = (0..to).find_map(|i| self.indent(i)).unwrap_or(0);
        for (depth, key) in path.iter().enumerate() {
            let hit = (from..to).find(|&i| {
                matches!(&self.kinds[i], Kind::Entry(e) if e.indent == indent && e.key == *key)
            });
            let Some(i) = hit else {
                let at = Parent::Block { from, to, indent };
                return Ok(Found::Missing { at, rest: depth });
            };
            if depth + 1 == path.len() {
                return Ok(Found::Line(i));
            }
            let e = self.entry(i);
            if e.value.0 < e.value.1 {
                // A one-line flow mapping holds the last key of the path.
                if depth + 2 != path.len() {
                    return error(i, format!("{key} is not a block mapping"));
                }
                let items = flow_items(i, &self.lines[i], e.value)?;
                let last = path[depth + 1];
                return Ok(match items.into_iter().find(|(k, _)| k == last) {
                    Some((_, v)) => Found::Flow(i, v),
                    None => Found::Missing {
                        at: Parent::Flow(i, e.value),
                        rest: depth + 1,
                    },
                });
            }
            let (f, t, inner) = self.block_of(i);
            if let Some(Kind::Other(_)) = (f..t)
                .map(|j| &self.kinds[j])
                .find(|k| !matches!(k, Kind::Blank))
            {
                return error(i, format!("{key} is not a mapping"));
            }
            (from, to) = (f, t);
            indent = inner.unwrap_or(e.indent + 2);
        }
        Ok(Found::Missing {
            at: Parent::Block { from, to, indent },
            rest: path.len(),
        })
    }

    /// The scalar at `path`, unquoted; `None` when the key is not there.
    pub fn get(&self, path: &[&str]) -> Result<Option<String>, Error> {
        Ok(match self.find(path)? {
            Found::Line(i) => {
                let (s, e) = self.entry(i).value;
                (s < e).then(|| unquote(&self.lines[i][s..e]))
            }
            Found::Flow(i, (s, e)) => Some(unquote(&self.lines[i][s..e])),
            Found::Missing { .. } => None,
        })
    }

    /// Whether `path` is there.
    pub fn has(&self, path: &[&str]) -> Result<bool, Error> {
        Ok(!matches!(self.find(path)?, Found::Missing { .. }))
    }

    /// The comment on the line that holds `path`, without its `#`.
    pub fn comment(&self, path: &[&str]) -> Result<Option<&str>, Error> {
        let i = match self.find(path)? {
            Found::Line(i) | Found::Flow(i, _) => i,
            Found::Missing { .. } => return Ok(None),
        };
        let line = &self.lines[i];
        Ok(self.entry(i).comment.map(|c| line[c + 1..].trim()))
    }

    /// The keys of the mapping at `path` and their values as written (empty
    /// for a key whose mapping follows below it), in the file's order.
    pub fn entries(&self, path: &[&str]) -> Result<Vec<(String, String)>, Error> {
        let i = match self.find(path)? {
            Found::Line(i) => i,
            _ => return Ok(Vec::new()),
        };
        let e = self.entry(i);
        if e.value.0 < e.value.1 {
            let items = flow_items(i, &self.lines[i], e.value)?;
            let line = &self.lines[i];
            return Ok(items
                .into_iter()
                .map(|(k, (s, t))| (k, line[s..t].to_owned()))
                .collect());
        }
        let (from, to, inner) = self.block_of(i);
        let entries = (from..to).filter_map(|j| match &self.kinds[j] {
            Kind::Entry(c) if Some(c.indent) == inner => Some((
                c.key.clone(),
                self.lines[j][c.value.0..c.value.1].to_owned(),
            )),
            _ => None,
        });
        Ok(entries.collect())
    }

    /// Sets the scalar at `path` to `raw` (YAML text, quoted as it must be),
    /// replacing only the old value's text; a key that is not there is added
    /// after the last line of its mapping (and the mappings above it that
    /// are missing too, as blocks).
    pub fn set(&mut self, path: &[&str], raw: &str) -> Result<(), Error> {
        match self.find(path)? {
            Found::Line(i) => {
                let (s, e) = self.entry(i).value;
                if s == e && self.block_of(i).2.is_some() {
                    return error(i, format!("{} is a mapping", path.join(".")));
                }
                // A key with no value has no space after its colon yet.
                let raw = if s == e && !self.lines[i][..s].ends_with(' ') {
                    format!(" {raw}")
                } else {
                    raw.to_owned()
                };
                self.lines[i].replace_range(s..e, &raw);
            }
            Found::Flow(i, (s, e)) => self.lines[i].replace_range(s..e, raw),
            Found::Missing {
                at: Parent::Flow(i, (_, e)),
                rest,
            } => {
                let empty = self.lines[i][..e - 1].trim_end().ends_with('{');
                let item = format!(
                    "{}{}: {raw}",
                    if empty { "" } else { ", " },
                    key_text(path[rest])
                );
                self.lines[i].insert_str(e - 1, &item);
            }
            Found::Missing {
                at: Parent::Block { from, to, indent },
                rest,
            } => {
                // After the mapping's last line, before the comments and
                // blank lines that lead into what follows it.
                let after = (from..to)
                    .rev()
                    .find(|&j| self.indent(j).is_some())
                    .map_or(from, |j| j + 1);
                let mut new = Vec::new();
                for (d, key) in path[rest..].iter().enumerate() {
                    let pad = " ".repeat(indent + 2 * d);
                    let value = if rest + d + 1 == path.len() {
                        format!(" {raw}")
                    } else {
                        String::new()
                    };
                    new.push(format!("{pad}{}:{value}", key_text(key)));
                }
                self.lines.splice(after..after, new);
            }
        }
        self.reparse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"---
# A heading comment.
site:
  # Fleet-wide.
  power: {"24": 22, "5": 26}   # dBm
  radios:
    "24": {hw_mode: g, channel: 13}
  aps:
    ap1:
      keys:
        - ssh-ed25519 AAAA
      radios:
        # Kept: the neighbour's primary.
        "5":   # planner: fixed
          channel: 44
          ht_capab: "[HT40+]"
          text: 'it''s # not a comment'

        # 6 GHz.
        "6":
          channel: 37
    ap2:
      empty:
  # Trailing: belongs to the next key.
  test: {}
"#;

    #[test]
    fn reads_scalars_through_blocks_and_flow_mappings() {
        let d = Doc::parse(DOC).unwrap();
        let get = |p: &[&str]| d.get(p).unwrap();
        assert_eq!(get(&["site", "power", "5"]).as_deref(), Some("26"));
        assert_eq!(
            get(&["site", "radios", "24", "channel"]).as_deref(),
            Some("13")
        );
        assert_eq!(
            get(&["site", "aps", "ap1", "radios", "5", "channel"]).as_deref(),
            Some("44")
        );
        assert_eq!(
            get(&["site", "aps", "ap1", "radios", "5", "ht_capab"]).as_deref(),
            Some("[HT40+]")
        );
        assert_eq!(
            get(&["site", "aps", "ap1", "radios", "5", "text"]).as_deref(),
            Some("it's # not a comment")
        );
        assert_eq!(
            get(&["site", "aps", "ap1", "radios", "6", "channel"]).as_deref(),
            Some("37")
        );
        assert_eq!(get(&["site", "aps", "ap2", "radios", "5"]), None);
        assert_eq!(get(&["site", "aps", "ap2", "empty"]), None);
        assert_eq!(
            d.comment(&["site", "aps", "ap1", "radios", "5"]).unwrap(),
            Some("planner: fixed")
        );
        assert_eq!(d.comment(&["site", "power", "24"]).unwrap(), Some("dBm"));
        assert_eq!(
            d.comment(&["site", "aps", "ap1", "radios", "6"]).unwrap(),
            None
        );
        let keys: Vec<_> = d
            .entries(&["site", "aps"])
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(keys, ["ap1", "ap2"]);
        assert_eq!(
            d.entries(&["site", "radios", "24"]).unwrap(),
            [
                ("hw_mode".into(), "g".into()),
                ("channel".into(), "13".into())
            ]
        );
        // A sequence is no mapping to look into.
        assert!(d.get(&["site", "aps", "ap1", "keys", "x"]).is_err());
    }

    /// The lines that differ between two texts, as (old, new) pairs.
    fn changed(a: &str, b: &str) -> Vec<(String, String)> {
        a.lines()
            .zip(b.lines())
            .filter(|(x, y)| x != y)
            .map(|(x, y)| (x.into(), y.into()))
            .collect()
    }

    #[test]
    fn a_value_is_replaced_in_place() {
        let mut d = Doc::parse(DOC).unwrap();
        d.set(&["site", "aps", "ap1", "radios", "5", "channel"], "48")
            .unwrap();
        d.set(&["site", "power", "5"], "23").unwrap();
        d.set(&["site", "radios", "24", "channel"], "9").unwrap();
        d.set(
            &["site", "aps", "ap1", "radios", "5", "ht_capab"],
            "\"[HT40-]\"",
        )
        .unwrap();
        let out = d.text();
        assert_eq!(out.lines().count(), DOC.lines().count());
        assert_eq!(
            changed(DOC, &out),
            [
                (
                    "  power: {\"24\": 22, \"5\": 26}   # dBm".into(),
                    "  power: {\"24\": 22, \"5\": 23}   # dBm".into()
                ),
                (
                    "    \"24\": {hw_mode: g, channel: 13}".into(),
                    "    \"24\": {hw_mode: g, channel: 9}".into()
                ),
                (
                    "          channel: 44".into(),
                    "          channel: 48".into()
                ),
                (
                    "          ht_capab: \"[HT40+]\"".into(),
                    "          ht_capab: \"[HT40-]\"".into()
                ),
            ]
        );
        assert!(out.ends_with("test: {}\n"));
    }

    #[test]
    fn a_missing_key_is_added_where_its_mapping_ends() {
        let mut d = Doc::parse(DOC).unwrap();
        d.set(
            &["site", "aps", "ap1", "radios", "5", "he_oper_chwidth"],
            "1",
        )
        .unwrap();
        d.set(&["site", "aps", "ap2", "radios", "24", "channel"], "9")
            .unwrap();
        d.set(&["site", "aps", "ap1", "power", "6"], "20").unwrap();
        d.set(&["site", "power", "6"], "26").unwrap();
        d.set(&["site", "test", "a"], "1").unwrap();
        d.set(&["site", "aps", "ap2", "empty"], "x").unwrap();
        let want = DOC
            .replace(
                "text: 'it''s # not a comment'\n",
                "text: 'it''s # not a comment'\n          he_oper_chwidth: 1\n",
            )
            .replace(
                "          channel: 37\n",
                "          channel: 37\n      power:\n        \"6\": 20\n",
            )
            .replace(
                "      empty:\n",
                "      empty: x\n      radios:\n        \"24\":\n          channel: 9\n",
            )
            .replace("\"5\": 26}", "\"5\": 26, \"6\": 26}")
            .replace("test: {}", "test: {a: 1}");
        assert_eq!(d.text(), want);
        assert_eq!(
            d.get(&["site", "aps", "ap2", "radios", "24", "channel"])
                .unwrap()
                .as_deref(),
            Some("9")
        );
    }

    #[test]
    fn what_it_does_not_understand_is_an_error() {
        assert!(Doc::parse("a:\n\tb: 1\n").is_err());
        assert!(Doc::parse("a: \"open\n").is_err());
        let d = Doc::parse("a: {b: {c: 1}}\nm:\n  n: 1\n").unwrap();
        assert!(d.get(&["a", "b"]).is_err());
        let mut d = Doc::parse("m:\n  n: 1\n").unwrap();
        assert!(d.set(&["m"], "1").is_err());
    }
}
