//! Media types for vault files (ADR 2026-10-15 vault files; CONTRACT-246 raw
//! byte route).
//!
//! The raw byte route serves the **real** `Content-Type` from [`content_type_for_name`] (D1).
//! Safety for the types a browser could execute or style comes from the transport's headers
//! (`nosniff`, CSP `sandbox`, `CORP: same-origin`, `Sec-Fetch-Dest` refusals) plus
//! `Content-Disposition: attachment` for every [`is_active_type`]. Pure functions over names and
//! type strings; no charset parameter is ever added. A type does not say whether the bytes are
//! text (`svgz` shares `image/svg+xml` with `svg` but is gzip), so no text hint is derived here.

/// The type of anything the table does not name.
pub const OCTET_STREAM: &str = "application/octet-stream";

/// Longer suffixes are not extensions in the table; they short-cut to [`OCTET_STREAM`].
const MAX_EXTENSION_BYTES: usize = 16;

/// The `Content-Type` for a file name (or a `/`-separated path: only its last component counts),
/// by the lowercase ASCII text after the last `.`. A leading-dot name's suffix counts, so `.env`
/// is `env`. Unknown, empty or overlong extensions → [`OCTET_STREAM`].
pub fn content_type_for_name(name: &str) -> &'static str {
    let name = name.rsplit('/').next().unwrap_or(name);
    let Some((_, extension)) = name.rsplit_once('.') else {
        return OCTET_STREAM;
    };
    if extension.is_empty() || extension.len() > MAX_EXTENSION_BYTES {
        return OCTET_STREAM;
    }
    match extension.to_ascii_lowercase().as_str() {
        // Text.
        "txt" | "log" | "out" => "text/plain",
        "md" | "markdown" => "text/markdown",
        "csv" => "text/csv",
        "tsv" | "tab" => "text/tab-separated-values",
        "json" | "canvas" | "excalidraw" => "application/json",
        "jsonl" | "ndjson" => "application/x-ndjson",
        "yaml" | "yml" => "application/yaml",
        "toml" => "application/toml",
        "ipynb" => "application/x-ipynb+json",
        "xml" | "plist" | "xsl" | "xslt" => "application/xml",
        "html" | "htm" => "text/html",
        "xhtml" => "application/xhtml+xml",
        "css" => "text/css",
        "js" | "mjs" => "text/javascript",
        "rs" | "py" | "swift" | "ts" | "tsx" | "jsx" | "sh" | "zsh" | "go" | "c" | "h" | "cpp"
        | "java" | "kt" | "rb" | "php" | "sql" | "ini" | "cfg" | "conf" | "env" | "mmd"
        | "mermaid" => "text/plain",
        // The VCS control files are listed and readable (ADR 2026-10-15); they are plain text.
        "gitignore" | "gitattributes" | "gitmodules" => "text/plain",
        // Images.
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "heic" => "image/heic",
        "heif" => "image/heif",
        "tif" | "tiff" => "image/tiff",
        "bmp" => "image/bmp",
        "ico" => "image/vnd.microsoft.icon",
        "svg" | "svgz" => "image/svg+xml",
        "psd" => "image/vnd.adobe.photoshop",
        // Audio and video.
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "ogg" => "audio/ogg",
        "opus" => "audio/opus",
        "aif" | "aiff" => "audio/aiff",
        "caf" => "audio/x-caf",
        "mp4" => "video/mp4",
        "m4v" => "video/x-m4v",
        "mov" => "video/quicktime",
        "webm" => "video/webm",
        "mkv" => "video/x-matroska",
        // Documents.
        "pdf" => "application/pdf",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "doc" => "application/msword",
        "xls" => "application/vnd.ms-excel",
        "ppt" => "application/vnd.ms-powerpoint",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "odp" => "application/vnd.oasis.opendocument.presentation",
        "rtf" => "application/rtf",
        "pages" => "application/vnd.apple.pages",
        "numbers" => "application/vnd.apple.numbers",
        "key" => "application/vnd.apple.keynote",
        "epub" => "application/epub+zip",
        // Archives, fonts, 3D.
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "tar" => "application/x-tar",
        "7z" => "application/x-7z-compressed",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "usdz" => "model/vnd.usdz+zip",
        "glb" => "model/gltf-binary",
        "gltf" => "model/gltf+json",
        _ => OCTET_STREAM,
    }
}

/// `true` for types a browser may execute or apply as markup, script or style: `text/html`,
/// `application/xhtml+xml`, `image/svg+xml`, `application/xml`, `text/xml`, `text/javascript`,
/// `text/css`, the legacy JavaScript aliases, and any `+xml` structured suffix. Parameters and
/// letter case are ignored. The raw route sends these with `Content-Disposition: attachment`.
pub fn is_active_type(content_type: &str) -> bool {
    let essence = essence(content_type);
    matches!(
        essence.as_str(),
        "text/html"
            | "application/xhtml+xml"
            | "image/svg+xml"
            | "application/xml"
            | "text/xml"
            | "text/javascript"
            | "text/css"
            | "application/javascript"
            | "application/x-javascript"
            | "application/ecmascript"
            | "text/ecmascript"
    ) || essence.ends_with("+xml")
}

/// `type/subtype` without parameters, trimmed and lowercased.
fn essence(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_of_ext(extension: &str) -> &'static str {
        content_type_for_name(&format!("file.{extension}"))
    }

    /// The CONTRACT-246 media table, written out independently of the implementation.
    const TABLE: &[(&[&str], &str)] = &[
        (&["txt", "log", "out"], "text/plain"),
        (&["md", "markdown"], "text/markdown"),
        (&["csv"], "text/csv"),
        (&["tsv", "tab"], "text/tab-separated-values"),
        (&["json", "canvas", "excalidraw"], "application/json"),
        (&["jsonl", "ndjson"], "application/x-ndjson"),
        (&["yaml", "yml"], "application/yaml"),
        (&["toml"], "application/toml"),
        (&["ipynb"], "application/x-ipynb+json"),
        (&["xml", "plist", "xsl", "xslt"], "application/xml"),
        (&["html", "htm"], "text/html"),
        (&["xhtml"], "application/xhtml+xml"),
        (&["css"], "text/css"),
        (&["js", "mjs"], "text/javascript"),
        (
            &[
                "rs", "py", "swift", "ts", "tsx", "jsx", "sh", "zsh", "go", "c", "h", "cpp",
                "java", "kt", "rb", "php", "sql", "ini", "cfg", "conf", "env", "mmd", "mermaid",
            ],
            "text/plain",
        ),
        (&["png"], "image/png"),
        (&["jpg", "jpeg"], "image/jpeg"),
        (&["gif"], "image/gif"),
        (&["webp"], "image/webp"),
        (&["avif"], "image/avif"),
        (&["heic"], "image/heic"),
        (&["heif"], "image/heif"),
        (&["tif", "tiff"], "image/tiff"),
        (&["bmp"], "image/bmp"),
        (&["ico"], "image/vnd.microsoft.icon"),
        (&["svg", "svgz"], "image/svg+xml"),
        (&["psd"], "image/vnd.adobe.photoshop"),
        (&["mp3"], "audio/mpeg"),
        (&["m4a"], "audio/mp4"),
        (&["aac"], "audio/aac"),
        (&["wav"], "audio/wav"),
        (&["flac"], "audio/flac"),
        (&["ogg"], "audio/ogg"),
        (&["opus"], "audio/opus"),
        (&["aif", "aiff"], "audio/aiff"),
        (&["caf"], "audio/x-caf"),
        (&["mp4"], "video/mp4"),
        (&["m4v"], "video/x-m4v"),
        (&["mov"], "video/quicktime"),
        (&["webm"], "video/webm"),
        (&["mkv"], "video/x-matroska"),
        (&["pdf"], "application/pdf"),
        (
            &["docx"],
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        (
            &["xlsx"],
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
        (
            &["pptx"],
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ),
        (&["doc"], "application/msword"),
        (&["xls"], "application/vnd.ms-excel"),
        (&["ppt"], "application/vnd.ms-powerpoint"),
        (&["odt"], "application/vnd.oasis.opendocument.text"),
        (&["ods"], "application/vnd.oasis.opendocument.spreadsheet"),
        (&["odp"], "application/vnd.oasis.opendocument.presentation"),
        (&["rtf"], "application/rtf"),
        (&["pages"], "application/vnd.apple.pages"),
        (&["numbers"], "application/vnd.apple.numbers"),
        (&["key"], "application/vnd.apple.keynote"),
        (&["epub"], "application/epub+zip"),
        (&["zip"], "application/zip"),
        (&["gz", "tgz"], "application/gzip"),
        (&["tar"], "application/x-tar"),
        (&["7z"], "application/x-7z-compressed"),
        (&["ttf"], "font/ttf"),
        (&["otf"], "font/otf"),
        (&["woff"], "font/woff"),
        (&["woff2"], "font/woff2"),
        (&["usdz"], "model/vnd.usdz+zip"),
        (&["glb"], "model/gltf-binary"),
        (&["gltf"], "model/gltf+json"),
    ];

    #[test]
    fn transport_table_rows() {
        for (extensions, expected) in TABLE {
            for extension in *extensions {
                assert_eq!(type_of_ext(extension), *expected, "extension {extension}");
            }
        }
    }

    #[test]
    fn extension_lookup_rules() {
        assert_eq!(content_type_for_name("Photo.PNG"), "image/png");
        assert_eq!(content_type_for_name("Notes.Md"), "text/markdown");
        assert_eq!(content_type_for_name("archive.tar.gz"), "application/gzip");
        assert_eq!(content_type_for_name(".env"), "text/plain");
        assert_eq!(content_type_for_name("notes/report.md"), "text/markdown");
        assert_eq!(content_type_for_name("dir.d/file"), OCTET_STREAM);
        assert_eq!(content_type_for_name("Makefile"), OCTET_STREAM);
        assert_eq!(content_type_for_name("x."), OCTET_STREAM);
        assert_eq!(content_type_for_name(""), OCTET_STREAM);
        assert_eq!(content_type_for_name("x.unknownext"), OCTET_STREAM);
        assert_eq!(
            content_type_for_name("x.verylongextensionname"),
            OCTET_STREAM
        );
        assert_eq!(content_type_for_name("x.m\u{E4}"), OCTET_STREAM);
        for name in [".gitignore", "p/.gitattributes", ".gitmodules"] {
            assert_eq!(content_type_for_name(name), "text/plain", "{name}");
        }
    }

    #[test]
    fn active_types() {
        for active in [
            "text/html",
            "application/xhtml+xml",
            "image/svg+xml",
            "application/xml",
            "text/xml",
            "text/javascript",
            "text/css",
            "Text/HTML; charset=utf-8",
            " text/css ",
            "application/javascript",
            "application/rss+xml",
        ] {
            assert!(is_active_type(active), "{active:?} must be active");
        }
        for extension in [
            "html", "htm", "xhtml", "svg", "svgz", "xml", "plist", "xsl", "xslt", "js", "mjs",
            "css",
        ] {
            assert!(is_active_type(type_of_ext(extension)), "{extension}");
        }
        for inactive in [
            "text/plain",
            "text/markdown",
            "application/json",
            "image/png",
            "application/pdf",
            "model/gltf+json",
            OCTET_STREAM,
            "",
        ] {
            assert!(!is_active_type(inactive), "{inactive:?} must not be active");
        }
    }
}
