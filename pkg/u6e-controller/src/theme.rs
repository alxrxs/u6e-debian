//! The operator's branding of the web UI (`[ui]`): a name shown before
//! "Wi-Fi" in the header and the tab's title (`brand`), and a directory of
//! their own files (`theme`), served at `/theme/` like the rest of the UI,
//! its `theme.css` loaded after the built-in stylesheet when it is there.
//! The stylesheet restyles the UI by its custom properties on `:root`; its
//! `url()`s resolve under `/theme/`, so its fonts and logo sit beside it.
//!
//! A theme file is named by plain path segments (letters, digits, `.`, `_`,
//! `-`, none starting with a dot) and one of the extensions a stylesheet
//! uses, and must resolve inside the directory; anything else is not found.
//! Each is read at its request and revalidated by its hash, so a changed
//! file counts on the next load.

use std::path::{Path, PathBuf};

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::http;

/// The longest brand, in characters.
pub const BRAND_MAX: usize = 64;

/// The `[ui]` section, checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    pub brand: Option<String>,
    pub theme: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    brand: Option<String>,
    theme: Option<PathBuf>,
}

impl File {
    /// A brand of 1 to 64 characters, none a control character, and an
    /// absolute theme directory.
    pub fn check(self) -> Result<Settings, String> {
        if let Some(b) = &self.brand
            && (b.trim().is_empty()
                || b.chars().count() > BRAND_MAX
                || b.chars().any(char::is_control))
        {
            return Err(format!(
                "ui.brand is not 1 to {BRAND_MAX} characters without control characters"
            ));
        }
        if self.theme.as_ref().is_some_and(|t| !t.is_absolute()) {
            return Err("ui.theme is not an absolute path".into());
        }
        Ok(Settings {
            brand: self.brand,
            theme: self.theme,
        })
    }
}

/// `text` safe inside an element or a quoted attribute.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The page `template` with the brand and the theme's stylesheet in place.
pub fn page(template: &str, ui: &Settings) -> String {
    let brand = ui.brand.as_deref().map(escape);
    let name = match &brand {
        Some(b) => format!("{b} Wi-Fi"),
        None => "Wi-Fi".into(),
    };
    let brand_html = brand.map_or_else(String::new, |b| {
        format!("<span class=\"brand-name\">{b}</span> ")
    });
    let styled = ui
        .theme
        .as_ref()
        .is_some_and(|d| d.join("theme.css").is_file());
    let theme_html = if styled {
        "<link rel=\"stylesheet\" href=\"/theme/theme.css\">"
    } else {
        ""
    };
    template
        .replace("{{name}}", &name)
        .replace("{{brand}}", &brand_html)
        .replace("{{theme}}", theme_html)
}

/// The content type of a theme file named `path`, if it may be served.
fn kind(path: &str) -> Option<&'static str> {
    let plain = |s: &str| {
        !s.is_empty()
            && !s.starts_with('.')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    };
    if path.len() > 255 || !path.split('/').all(plain) {
        return None;
    }
    Some(match path.rsplit_once('.')?.1 {
        "css" => "text/css; charset=utf-8",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "webp" => "image/webp",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/vnd.microsoft.icon",
        _ => return None,
    })
}

/// The theme file `path` under `dir`, revalidated on each load.
pub async fn file(dir: Option<&Path>, path: &str, req: &HeaderMap) -> Response {
    let not_found = || StatusCode::NOT_FOUND.into_response();
    let (Some(dir), Some(kind)) = (dir, kind(path)) else {
        return not_found();
    };
    // A symbolic link out of the directory is refused as `..` is.
    let Ok(root) = tokio::fs::canonicalize(dir).await else {
        return not_found();
    };
    let Ok(full) = tokio::fs::canonicalize(root.join(path)).await else {
        return not_found();
    };
    if !full.starts_with(&root) {
        return not_found();
    }
    match tokio::fs::read(&full).await {
        Ok(body) => {
            let etag = http::tag(&body);
            http::cached(req, kind, body, &etag, "no-cache")
        }
        Err(_) => not_found(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    fn check(brand: Option<&str>, theme: Option<&str>) -> Result<Settings, String> {
        File {
            brand: brand.map(str::to_owned),
            theme: theme.map(PathBuf::from),
        }
        .check()
    }

    #[test]
    fn the_brand_is_a_short_line_and_the_theme_an_absolute_directory() {
        assert_eq!(check(None, None), Ok(Settings::default()));
        let s = check(Some("Example Org"), Some("/etc/u6e-controller/theme")).unwrap();
        assert_eq!(s.brand.as_deref(), Some("Example Org"));
        assert!(check(Some(""), None).is_err());
        assert!(check(Some("  "), None).is_err());
        assert!(check(Some("a\nb"), None).is_err());
        assert!(check(Some(&"x".repeat(65)), None).is_err());
        assert!(check(Some(&"é".repeat(64)), None).is_ok());
        assert!(check(None, Some("theme")).is_err());
    }

    const TEMPLATE: &str = "<title>{{name}}</title>{{theme}}<a><span>{{brand}}Wi-Fi</span></a>";

    #[test]
    fn the_page_names_the_brand_escaped_and_links_the_stylesheet_only_when_there() {
        assert_eq!(
            page(TEMPLATE, &Settings::default()),
            "<title>Wi-Fi</title><a><span>Wi-Fi</span></a>"
        );
        let dir = TestDir::new();
        let ui = Settings {
            brand: Some("A&B <\"x\">".into()),
            theme: Some(dir.path().to_owned()),
        };
        let esc = "A&amp;B &lt;&quot;x&quot;&gt;";
        assert_eq!(
            page(TEMPLATE, &ui),
            format!(
                "<title>{esc} Wi-Fi</title><a><span><span class=\"brand-name\">{esc}</span> Wi-Fi</span></a>"
            )
        );
        std::fs::write(dir.path().join("theme.css"), ":root {}").unwrap();
        assert!(
            page(TEMPLATE, &ui).contains("<link rel=\"stylesheet\" href=\"/theme/theme.css\">")
        );
    }

    #[test]
    fn only_plain_names_of_a_stylesheets_types_are_served() {
        assert_eq!(kind("theme.css"), Some("text/css; charset=utf-8"));
        assert_eq!(kind("fonts/Sans-VF.woff2"), Some("font/woff2"));
        assert_eq!(kind("logo.webp"), Some("image/webp"));
        for bad in [
            "",
            "theme",
            "theme.html",
            "../theme.css",
            "fonts/../theme.css",
            ".hidden.css",
            "fonts//a.woff2",
            "/etc/a.css",
            "a b.css",
            "a\\b.css",
            "theme.CSS",
        ] {
            assert_eq!(kind(bad), None, "{bad}");
        }
    }

    fn get(dir: Option<&Path>, path: &str) -> (StatusCode, Option<String>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let resp = rt.block_on(file(dir, path, &HeaderMap::new()));
        let kind = resp
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_owned());
        (resp.status(), kind)
    }

    #[test]
    fn a_file_is_served_from_inside_the_directory_alone() {
        let outside = TestDir::new();
        std::fs::write(outside.path().join("secret.css"), "x").unwrap();
        let dir = TestDir::new();
        std::fs::create_dir(dir.path().join("fonts")).unwrap();
        std::fs::write(dir.path().join("theme.css"), ":root {}").unwrap();
        std::fs::write(dir.path().join("fonts/a.woff2"), "w").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.css"),
            dir.path().join("out.css"),
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("away")).unwrap();
        let d = Some(dir.path());
        assert_eq!(
            get(d, "theme.css"),
            (StatusCode::OK, Some("text/css; charset=utf-8".into()))
        );
        assert_eq!(
            get(d, "fonts/a.woff2"),
            (StatusCode::OK, Some("font/woff2".into()))
        );
        for missing in [
            "nope.css",
            "out.css",
            "away/secret.css",
            "fonts.css",
            "fonts",
        ] {
            assert_eq!(get(d, missing).0, StatusCode::NOT_FOUND, "{missing}");
        }
        // Without a theme directory, nothing is.
        assert_eq!(get(None, "theme.css").0, StatusCode::NOT_FOUND);
    }
}
