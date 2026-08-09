//! Slice-B hardcoded runtime built-in template contents.
//!
//! Four templates per MODULE-005 §1.4.3 "Runtime built-in minimum set":
//! - `explorer` — fs(RO) + memory + llm, for exploration
//! - `planner` — fs(RO) + memory + llm, for plan design
//! - `reviewer` — fs(RO) + memory + llm, for review
//! - `general-purpose` — inherits parent's full capabilities
//!
//! Manifest YAML deliberately omits the `kind:` line so `apply_template`'s
//! manifest kind-mismatch check is a no-op (the template is usable for
//! both `kind: Child` and `kind: Sub` spawns). Each AGENTS.md carries the
//! "Self-Improvement Guidelines" marker required by AC-19.
//!
//! `skills` is empty for all four built-ins in Slice B (the structural
//! surface is exercised by templates.rs/apply_template; skill payload
//! delivery is a Slice C concern for the pack adapter). `memory_seed_jsonl`
//! ships an empty file content (`""`) for child-only seeding — exercised
//! by AC-09 to confirm seeded contents are written for `kind: Child` and
//! never for `kind: Sub`.

use crate::templates::TemplateContent;

const EXPLORER_AGENTS_MD: &str = "# Self-Improvement Guidelines (explorer template)\n\n\
You are an exploration sub-agent. Your job is to discover, enumerate, and\n\
catalogue information without making mutating changes.\n";

const PLANNER_AGENTS_MD: &str = "# Self-Improvement Guidelines (planner template)\n\n\
You are a planning sub-agent. Decompose tasks into ordered, dependency-aware\n\
sub-tasks. Surface assumptions explicitly.\n";

const REVIEWER_AGENTS_MD: &str = "# Self-Improvement Guidelines (reviewer template)\n\n\
You are a review sub-agent. Apply structured critique and flag risks; do not\n\
modify the artefact under review.\n";

const GENERAL_PURPOSE_AGENTS_MD: &str =
    "# Self-Improvement Guidelines (general-purpose template)\n\n\
You inherit the parent agent's full capabilities. Use them only as required\n\
for the delegated task and surface notable side effects.\n";

const EXPLORER_MANIFEST: &str = "name: \"explorer\"\n\
description: \"Read-only exploration sub-agent (Slice B built-in template).\"\n\
default-model: \"sonnet\"\n";

const PLANNER_MANIFEST: &str = "name: \"planner\"\n\
description: \"Plan-decomposition sub-agent (Slice B built-in template).\"\n\
default-model: \"sonnet\"\n";

const REVIEWER_MANIFEST: &str = "name: \"reviewer\"\n\
description: \"Critique-and-flag sub-agent (Slice B built-in template).\"\n\
default-model: \"sonnet\"\n";

const GENERAL_PURPOSE_MANIFEST: &str = "name: \"general-purpose\"\n\
description: \"Inherits parent's full capabilities (Slice B built-in template).\"\n\
default-model: \"sonnet\"\n";

pub(crate) fn builtins() -> Vec<TemplateContent> {
    vec![
        TemplateContent {
            name: "explorer".to_string(),
            manifest_yaml: EXPLORER_MANIFEST.to_string(),
            agents_md: EXPLORER_AGENTS_MD.to_string(),
            skills: Vec::new(),
            memory_seed_jsonl: Some(String::new()),
            behavior_wasm: None,
        },
        TemplateContent {
            name: "planner".to_string(),
            manifest_yaml: PLANNER_MANIFEST.to_string(),
            agents_md: PLANNER_AGENTS_MD.to_string(),
            skills: Vec::new(),
            memory_seed_jsonl: Some(String::new()),
            behavior_wasm: None,
        },
        TemplateContent {
            name: "reviewer".to_string(),
            manifest_yaml: REVIEWER_MANIFEST.to_string(),
            agents_md: REVIEWER_AGENTS_MD.to_string(),
            skills: Vec::new(),
            memory_seed_jsonl: Some(String::new()),
            behavior_wasm: None,
        },
        TemplateContent {
            name: "general-purpose".to_string(),
            manifest_yaml: GENERAL_PURPOSE_MANIFEST.to_string(),
            agents_md: GENERAL_PURPOSE_AGENTS_MD.to_string(),
            skills: Vec::new(),
            memory_seed_jsonl: Some(String::new()),
            behavior_wasm: None,
        },
    ]
}
