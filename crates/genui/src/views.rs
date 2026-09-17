//! Entity view vocabulary (entity-data lane E3): every meta-schema view kind maps to exactly
//! one vetted catalog component, so a document an agent pushes and a view a client renders
//! from `/client/schema` go through the same renderer.

/// The view kinds a meta-schema aspect may declare, in declaration order.
pub const VIEW_KINDS: &[&str] = &["list", "table", "board", "calendar", "form"];

/// The catalog component that renders a schema view kind; `None` for an unknown kind.
///
/// `list` and `table` share `DataTable` (a list is a one-column table); `board` → `Board`
/// (columns from the `group_by` field's enum), `calendar` → `Calendar` (occurrences of the
/// view's query), `form` → `EntityForm` (one record, fields from the aspect).
pub fn component_for_view_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "list" | "table" => Some("DataTable"),
        "board" => Some("Board"),
        "calendar" => Some("Calendar"),
        "form" => Some("EntityForm"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_declared_kind_maps() {
        for kind in VIEW_KINDS {
            assert!(component_for_view_kind(kind).is_some(), "{kind}");
        }
        assert_eq!(component_for_view_kind("gantt"), None);
        assert_eq!(component_for_view_kind(""), None);
    }
}
