//! `BridgeOptions` = the `options_json` fields + a master key + a log sink (ADR D3).

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use advance_runtime_compose::{
    ComposeError, ComposeLog, HostPlatform, MasterKeyInput, NullComposeLog, PlatformRule,
    ProcessPolicy, Unsupported, WasmEngine,
};
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;

use crate::error::BridgeError;
use crate::types::CompositionProfile;

/// `BridgeOptions` = the `options_json` fields + a master key + a log sink (ADR D3).
#[non_exhaustive]
#[derive(Clone)]
pub struct BridgeOptions {
    pub platform: HostPlatform,
    pub composition: CompositionProfile,
    pub engine: Option<WasmEngine>,
    pub processes: Option<ProcessPolicy>,
    pub client_api: Option<BridgeClientApi>,
    pub state_root: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub master_key: MasterKeyInput,
    pub log: Arc<dyn ComposeLog>,
}

/// Client API requested by `options_json`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeClientApi {
    Loopback { port: u16 },
    Off,
}

impl BridgeOptions {
    /// Every key at its default for `platform`.
    pub fn new(platform: HostPlatform) -> Self {
        Self {
            platform,
            composition: CompositionProfile::Full,
            engine: None,
            processes: None,
            client_api: None,
            state_root: None,
            config_path: None,
            master_key: MasterKeyInput::FromConfig,
            log: Arc::new(NullComposeLog),
        }
    }

    /// Parse `options_json` (`None` ⇒ every default). Malformed JSON, a non-object document, a
    /// duplicate key, an unknown key (at any depth) or an unknown value → `InvalidConfig` (3); a
    /// combination the platform table forbids → `Unsupported` (14) (`check` with no extensions).
    pub fn from_json(options_json: Option<&str>) -> Result<Self, BridgeError> {
        let options = match options_json {
            None => Self::default(),
            Some(s) => parse_options_json(s)?,
        };
        options.check(HostPlatform::compiled(), 0)?;
        Ok(options)
    }

    pub fn with_master_key(mut self, key: MasterKeyInput) -> Self {
        self.master_key = key;
        self
    }

    pub fn with_log(mut self, log: Arc<dyn ComposeLog>) -> Self {
        self.log = log;
        self
    }

    pub fn with_state_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.state_root = Some(root.into());
        self
    }

    /// `engine.unwrap_or(platform.default_engine())`.
    pub fn resolved_engine(&self) -> WasmEngine {
        self.engine.unwrap_or(self.platform.default_engine())
    }

    /// `processes.unwrap_or(platform.default_processes())`.
    pub fn resolved_processes(&self) -> ProcessPolicy {
        self.processes.unwrap_or(self.platform.default_processes())
    }

    /// Pure validation. Production passes `HostPlatform::compiled()`; tests inject a compiled
    /// target. `from_json` runs this with `extensions = 0`.
    pub(crate) fn check(
        &self,
        compiled: Option<HostPlatform>,
        extensions: usize,
    ) -> Result<(), BridgeError> {
        if let Some(compiled) = compiled {
            if compiled.is_mobile() && self.platform != compiled {
                return Err(unsupported(Unsupported::PlatformMismatch { compiled }));
            }
        }
        if self.platform.is_mobile() {
            if self.resolved_engine() != WasmEngine::Pulley {
                return Err(unsupported(Unsupported::PlatformTable {
                    platform: self.platform,
                    rule: PlatformRule::Engine,
                }));
            }
            if self.resolved_processes() != ProcessPolicy::Forbid {
                return Err(unsupported(Unsupported::PlatformTable {
                    platform: self.platform,
                    rule: PlatformRule::Processes,
                }));
            }
        }
        if self.composition == CompositionProfile::HostOnly {
            if matches!(self.client_api, Some(BridgeClientApi::Loopback { .. })) {
                return Err(BridgeError::Unsupported(
                    r#"composition "host_only" has no Client API"#.into(),
                ));
            }
            if extensions > 0 {
                return Err(BridgeError::Unsupported(
                    r#"composition "host_only" takes no extensions"#.into(),
                ));
            }
        }
        Ok(())
    }
}

impl Default for BridgeOptions {
    fn default() -> Self {
        Self::new(HostPlatform::compiled().unwrap_or(HostPlatform::Linux))
    }
}

impl fmt::Debug for BridgeOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct LogPlaceholder;
        impl fmt::Debug for LogPlaceholder {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("<ComposeLog>")
            }
        }
        f.debug_struct("BridgeOptions")
            .field("platform", &self.platform)
            .field("composition", &self.composition)
            .field("engine", &self.engine)
            .field("processes", &self.processes)
            .field("client_api", &self.client_api)
            .field("state_root", &self.state_root)
            .field("config_path", &self.config_path)
            .field("master_key", &self.master_key)
            .field("log", &LogPlaceholder)
            .finish()
    }
}

fn unsupported(what: Unsupported) -> BridgeError {
    BridgeError::Unsupported(ComposeError::Unsupported(what).to_string())
}

fn parse_options_json(s: &str) -> Result<BridgeOptions, BridgeError> {
    let StrictValue(value) =
        serde_json::from_str(s).map_err(|e| BridgeError::InvalidConfig(e.to_string()))?;
    if !value.is_object() {
        return Err(BridgeError::InvalidConfig(
            "options_json must be an object".into(),
        ));
    }
    let dto: OptionsDto =
        serde_json::from_value(value).map_err(|e| BridgeError::InvalidConfig(e.to_string()))?;
    dto.into_options()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionsDto {
    #[serde(default)]
    platform: Option<PlatformWire>,
    #[serde(default)]
    composition: Option<CompositionProfile>,
    #[serde(default)]
    engine: Option<EngineWire>,
    #[serde(default)]
    processes: Option<ProcessesWire>,
    #[serde(default, deserialize_with = "client_api_from_json")]
    client_api: Option<BridgeClientApi>,
    #[serde(default)]
    state_root: Option<PathBuf>,
    #[serde(default)]
    config_path: Option<PathBuf>,
}

impl OptionsDto {
    fn into_options(self) -> Result<BridgeOptions, BridgeError> {
        let platform = match self.platform {
            Some(PlatformWire(p)) => p,
            None => HostPlatform::compiled().unwrap_or(HostPlatform::Linux),
        };
        Ok(BridgeOptions {
            platform,
            composition: self.composition.unwrap_or(CompositionProfile::Full),
            engine: self.engine.map(WasmEngine::from),
            processes: self.processes.map(ProcessPolicy::from),
            client_api: self.client_api,
            state_root: self.state_root,
            config_path: self.config_path,
            master_key: MasterKeyInput::FromConfig,
            log: Arc::new(NullComposeLog),
        })
    }
}

struct PlatformWire(HostPlatform);

impl<'de> Deserialize<'de> for PlatformWire {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map(PlatformWire).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EngineWire {
    Native,
    Pulley,
}

impl From<EngineWire> for WasmEngine {
    fn from(wire: EngineWire) -> Self {
        match wire {
            EngineWire::Native => WasmEngine::Native,
            EngineWire::Pulley => WasmEngine::Pulley,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProcessesWire {
    Allow,
    Forbid,
}

impl From<ProcessesWire> for ProcessPolicy {
    fn from(wire: ProcessesWire) -> Self {
        match wire {
            ProcessesWire::Allow => ProcessPolicy::Allow,
            ProcessesWire::Forbid => ProcessPolicy::Forbid,
        }
    }
}

fn client_api_from_json<'de, D>(deserializer: D) -> Result<Option<BridgeClientApi>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PortObject {
        port: u16,
    }
    match Option::<PortObject>::deserialize(deserializer)? {
        None => Ok(Some(BridgeClientApi::Off)),
        Some(PortObject { port }) => Ok(Some(BridgeClientApi::Loopback { port })),
    }
}

/// JSON value that refuses duplicate keys at every object depth.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(v)))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(v.into())))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(v.into())))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
        let n =
            serde_json::Number::from_f64(v).ok_or_else(|| de::Error::custom("invalid number"))?;
        Ok(StrictValue(Value::Number(n)))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(v.to_owned())))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(v)))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(StrictValue(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(StrictValue(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut object = serde_json::Map::new();
        while let Some((key, StrictValue(value))) = map.next_entry::<String, StrictValue>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate key \"{key}\"")));
            }
            object.insert(key, value);
        }
        Ok(StrictValue(Value::Object(object)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_runtime_compose::Zeroizing;

    fn parse_ok(json: &str) -> BridgeOptions {
        parse_options_json(json).unwrap_or_else(|e| panic!("parse {json}: {e}"))
    }

    fn from_json_err(json: Option<&str>) -> BridgeError {
        BridgeOptions::from_json(json).expect_err("expected InvalidConfig or Unsupported")
    }

    fn assert_invalid_config(json: &str) {
        let err = from_json_err(Some(json));
        assert!(
            matches!(err, BridgeError::InvalidConfig(_)),
            "{json}: {err:?}"
        );
        assert_eq!(err.c_code(), 3, "{json}");
    }

    fn assert_every_default(options: &BridgeOptions) {
        let expected = BridgeOptions::default();
        assert_eq!(options.platform, expected.platform);
        assert_eq!(options.composition, CompositionProfile::Full);
        assert_eq!(options.engine, None);
        assert_eq!(options.processes, None);
        assert_eq!(options.client_api, None);
        assert_eq!(options.state_root, None);
        assert_eq!(options.config_path, None);
        assert!(matches!(options.master_key, MasterKeyInput::FromConfig));
        assert_eq!(options.resolved_engine(), options.platform.default_engine());
        assert_eq!(
            options.resolved_processes(),
            options.platform.default_processes()
        );
    }

    #[test]
    fn module_001_ac32_options_json_null_and_empty_object_are_every_default() {
        assert_every_default(&BridgeOptions::from_json(None).expect("None"));
        assert_every_default(&BridgeOptions::from_json(Some("{}")).expect("{}"));
        assert_every_default(
            &BridgeOptions::from_json(Some(
                r#"{"platform":null,"composition":null,"engine":null,"processes":null,"state_root":null,"config_path":null}"#,
            ))
            .expect("null keys"),
        );
        for platform in [
            HostPlatform::MacOs,
            HostPlatform::Ios,
            HostPlatform::Android,
            HostPlatform::Windows,
            HostPlatform::Linux,
        ] {
            let options = BridgeOptions::new(platform);
            assert_eq!(options.resolved_engine(), platform.default_engine());
            assert_eq!(options.resolved_processes(), platform.default_processes());
        }
    }

    #[test]
    fn module_001_ac32_options_json_each_key_parses() {
        assert_eq!(
            parse_ok(r#"{"platform":"mac"}"#).platform,
            HostPlatform::MacOs
        );
        assert_eq!(
            parse_ok(r#"{"platform":"ios"}"#).platform,
            HostPlatform::Ios
        );
        assert_eq!(
            parse_ok(r#"{"platform":"android"}"#).platform,
            HostPlatform::Android
        );
        assert_eq!(
            parse_ok(r#"{"platform":"windows"}"#).platform,
            HostPlatform::Windows
        );
        assert_eq!(
            parse_ok(r#"{"platform":"linux"}"#).platform,
            HostPlatform::Linux
        );
        assert_eq!(
            parse_ok(r#"{"composition":"full"}"#).composition,
            CompositionProfile::Full
        );
        assert_eq!(
            parse_ok(r#"{"composition":"host_only"}"#).composition,
            CompositionProfile::HostOnly
        );
        assert_eq!(
            parse_ok(r#"{"engine":"native"}"#).engine,
            Some(WasmEngine::Native)
        );
        assert_eq!(
            parse_ok(r#"{"engine":"pulley"}"#).engine,
            Some(WasmEngine::Pulley)
        );
        assert_eq!(
            parse_ok(r#"{"processes":"allow"}"#).processes,
            Some(ProcessPolicy::Allow)
        );
        assert_eq!(
            parse_ok(r#"{"processes":"forbid"}"#).processes,
            Some(ProcessPolicy::Forbid)
        );
        assert_eq!(
            parse_ok(r#"{"client_api":{"port":9}}"#).client_api,
            Some(BridgeClientApi::Loopback { port: 9 })
        );
        assert_eq!(
            parse_ok(r#"{"state_root":"/tmp/sr"}"#)
                .state_root
                .as_deref(),
            Some(std::path::Path::new("/tmp/sr"))
        );
        assert_eq!(
            parse_ok(r#"{"config_path":".advance/runtime-config.yaml"}"#)
                .config_path
                .as_deref(),
            Some(std::path::Path::new(".advance/runtime-config.yaml"))
        );
    }

    #[test]
    fn module_001_ac32_options_json_malformed_document_is_invalid_config() {
        for json in ["{", "[]", "\"x\"", "1", ""] {
            assert_invalid_config(json);
        }
    }

    #[test]
    fn module_001_ac32_options_json_unknown_key_is_invalid_config() {
        assert_invalid_config(r#"{"nope":1}"#);
        assert_invalid_config(r#"{"client_api":{"port":0,"extra":true}}"#);
    }

    #[test]
    fn module_001_ac32_options_json_unknown_value_is_invalid_config() {
        assert_invalid_config(r#"{"platform":"beos"}"#);
        assert_invalid_config(r#"{"engine":"jit"}"#);
        assert_invalid_config(r#"{"processes":"maybe"}"#);
        assert_invalid_config(r#"{"client_api":{"port":70000}}"#);
        assert_invalid_config(r#"{"client_api":{"port":-1}}"#);
        assert_invalid_config(r#"{"client_api":{}}"#);
    }

    #[test]
    fn module_001_ac32_options_json_duplicate_key_is_invalid_config() {
        assert_invalid_config(r#"{"platform":"mac","platform":"linux"}"#);
        assert_invalid_config(r#"{"client_api":{"port":1,"port":2}}"#);
    }

    #[test]
    fn module_001_ac32_options_json_client_api_absent_null_object() {
        assert_eq!(parse_ok("{}").client_api, None);
        assert_eq!(
            parse_ok(r#"{"client_api":null}"#).client_api,
            Some(BridgeClientApi::Off)
        );
        assert_eq!(
            parse_ok(r#"{"client_api":{"port":7}}"#).client_api,
            Some(BridgeClientApi::Loopback { port: 7 })
        );
    }

    #[test]
    fn module_001_ac32_platform_table_refusals_answer_unsupported() {
        for platform in [HostPlatform::Ios, HostPlatform::Android] {
            let engine = BridgeOptions::from_json(Some(&format!(
                r#"{{"platform":"{platform}","engine":"native"}}"#
            )))
            .expect_err("native engine on mobile");
            assert_eq!(engine.c_code(), 14);
            assert_eq!(
                engine.to_string(),
                ComposeError::Unsupported(Unsupported::PlatformTable {
                    platform,
                    rule: PlatformRule::Engine,
                })
                .to_string()
            );

            let processes = BridgeOptions::from_json(Some(&format!(
                r#"{{"platform":"{platform}","processes":"allow"}}"#
            )))
            .expect_err("allow processes on mobile");
            assert_eq!(processes.c_code(), 14);
            assert_eq!(
                processes.to_string(),
                ComposeError::Unsupported(Unsupported::PlatformTable {
                    platform,
                    rule: PlatformRule::Processes,
                })
                .to_string()
            );
        }
    }

    #[test]
    fn module_001_ac32_compiled_mobile_target_refuses_other_labels() {
        for compiled in [HostPlatform::Ios, HostPlatform::Android] {
            for platform in [
                HostPlatform::MacOs,
                HostPlatform::Ios,
                HostPlatform::Android,
                HostPlatform::Windows,
                HostPlatform::Linux,
            ] {
                let result = BridgeOptions::new(platform).check(Some(compiled), 0);
                if platform == compiled {
                    result.expect("own label is valid");
                } else {
                    let err = result.expect_err("other labels refused");
                    assert_eq!(err.c_code(), 14);
                    assert_eq!(
                        err.to_string(),
                        ComposeError::Unsupported(Unsupported::PlatformMismatch { compiled })
                            .to_string()
                    );
                }
            }
        }
    }

    #[test]
    fn module_001_ac32_host_only_refuses_client_api_and_extensions() {
        let err = BridgeOptions::from_json(Some(
            r#"{"composition":"host_only","client_api":{"port":0}}"#,
        ))
        .expect_err("host_only + Loopback");
        assert_eq!(err.c_code(), 14);
        assert_eq!(
            err.to_string(),
            r#"composition "host_only" has no Client API"#
        );

        let host_only = BridgeOptions::from_json(Some(r#"{"composition":"host_only"}"#))
            .expect("host_only defaults");
        let err = host_only
            .check(HostPlatform::compiled(), 1)
            .expect_err("host_only + extensions");
        assert_eq!(err.c_code(), 14);
        assert_eq!(
            err.to_string(),
            r#"composition "host_only" takes no extensions"#
        );
    }

    #[test]
    fn module_001_ac32_bridge_options_debug_redacts_the_master_key() {
        let key = [7u8; 32];
        let options = BridgeOptions::default()
            .with_master_key(MasterKeyInput::Provided(Zeroizing::new(key)))
            .with_log(Arc::new(NullComposeLog))
            .with_state_root("/tmp/bridge-state");
        let debug = format!("{options:?}");
        assert!(
            debug.contains("Provided(<redacted>)"),
            "master_key Debug: {debug}"
        );
        assert!(
            !debug.contains("7, 7"),
            "key bytes must not appear: {debug}"
        );
        assert!(debug.contains("<ComposeLog>"), "log placeholder: {debug}");
    }
}
