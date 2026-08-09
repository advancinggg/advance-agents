//! db_tool — the agent-facing DB tool (MODULE-017-AC-31 / REQ-160).
//!
//! Exports `advance:runtime/tool-exports@0.1.0` (CONTRACT-163):
//!   - `describe()` → one method `query` (non-idempotent — it can `CREATE`/`INSERT`).
//!   - `execute("query", sql_bytes)` → runs REAL SQL inside THIS wasm sandbox over
//!     a fresh in-memory engine and returns the final `SELECT`'s rows as JSON
//!     (`[[1],[2]]`). `execute(other, _)` → `Err`.
//!
//! This is NOT an echo and NOT a host fn: the component genuinely tokenizes,
//! parses, and executes a bounded SQL subset (`CREATE TABLE` / `INSERT` /
//! `SELECT` with column projection + a `WHERE col = value` filter) entirely in
//! guest wasm — no host SQL/DB import, so MODULE-004's `rusqlite` index stays
//! agent-invisible. The engine is self-contained (ZERO external crates) so the
//! artifact builds deterministically for `wasm32-unknown-unknown` with no
//! network fetch / `getrandom` / WASI / C-toolchain (the repo's `echo_tool`
//! fixture pipeline). Malformed SQL / unknown methods fail CLOSED (`result::err`).

wit_bindgen::generate!({
    path: "wit",
    world: "db-tool",
});

use exports::advance::runtime::tool_exports::{Guest, MethodInfo, ToolDescription};
use std::collections::HashMap;

// Defensive bounds (the host also size-gates the component; these bound the
// in-guest work so a hostile SQL string cannot blow memory/CPU).
const MAX_SQL_BYTES: usize = 64 * 1024;
const MAX_TOKENS: usize = 8192;
const MAX_ROWS: usize = 4096;

// ── values ────────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
enum Value {
    Int(i64),
    Str(String),
}

// ── tokenizer ───────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
enum Tok {
    Word(String),
    Num(i64),
    Str(String),
    Sym(char),
}

fn tokenize(sql: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = sql.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if toks.len() > MAX_TOKENS {
            return Err("query too long (token cap exceeded)".to_string());
        }
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' | ')' | ',' | ';' | '*' | '=' => {
                toks.push(Tok::Sym(c));
                i += 1;
            }
            '\'' => {
                i += 1;
                let mut s = String::new();
                loop {
                    if i >= chars.len() {
                        return Err("unterminated string literal".to_string());
                    }
                    let ch = chars[i];
                    if ch == '\'' {
                        // SQL doubles a quote to escape it.
                        if i + 1 < chars.len() && chars[i + 1] == '\'' {
                            s.push('\'');
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    s.push(ch);
                    i += 1;
                }
                toks.push(Tok::Str(s));
            }
            '-' if i + 1 < chars.len() && chars[i + 1].is_ascii_digit() => {
                let start = i;
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let n: i64 = chars[start..i]
                    .iter()
                    .collect::<String>()
                    .parse()
                    .map_err(|_| "bad integer literal".to_string())?;
                toks.push(Tok::Num(n));
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let n: i64 = chars[start..i]
                    .iter()
                    .collect::<String>()
                    .parse()
                    .map_err(|_| "bad integer literal".to_string())?;
                toks.push(Tok::Num(n));
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                toks.push(Tok::Word(chars[start..i].iter().collect()));
            }
            other => return Err(format!("unexpected character: {other}")),
        }
    }
    Ok(toks)
}

// ── parser ────────────────────────────────────────────────────────────────

enum Proj {
    Star,
    Cols(Vec<String>),
}

enum Stmt {
    Create {
        table: String,
        cols: Vec<String>,
    },
    Insert {
        table: String,
        cols: Option<Vec<String>>,
        rows: Vec<Vec<Value>>,
    },
    Select {
        table: String,
        proj: Proj,
        filter: Option<(String, Value)>,
    },
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn new(toks: Vec<Tok>) -> Self {
        Self { toks, pos: 0 }
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat_sym(&mut self, c: char) -> Result<(), String> {
        match self.next() {
            Some(Tok::Sym(s)) if s == c => Ok(()),
            other => Err(format!("expected `{c}`, found {}", describe_tok(other.as_ref()))),
        }
    }

    fn peek_is_sym(&self, c: char) -> bool {
        matches!(self.peek(), Some(Tok::Sym(s)) if *s == c)
    }

    fn eat_kw(&mut self, kw: &str) -> Result<(), String> {
        match self.next() {
            Some(Tok::Word(w)) if w.eq_ignore_ascii_case(kw) => Ok(()),
            other => Err(format!(
                "expected keyword `{kw}`, found {}",
                describe_tok(other.as_ref())
            )),
        }
    }

    fn ident(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Tok::Word(w)) => Ok(w),
            other => Err(format!("expected identifier, found {}", describe_tok(other.as_ref()))),
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        match self.next() {
            Some(Tok::Num(n)) => Ok(Value::Int(n)),
            Some(Tok::Str(s)) => Ok(Value::Str(s)),
            other => Err(format!("expected a literal value, found {}", describe_tok(other.as_ref()))),
        }
    }

    fn parse_all(&mut self) -> Result<Vec<Stmt>, String> {
        let mut stmts = Vec::new();
        loop {
            while self.peek_is_sym(';') {
                self.pos += 1;
            }
            if self.peek().is_none() {
                break;
            }
            stmts.push(self.statement()?);
        }
        Ok(stmts)
    }

    fn statement(&mut self) -> Result<Stmt, String> {
        let kw = match self.peek() {
            Some(Tok::Word(w)) => w.to_ascii_uppercase(),
            other => return Err(format!("expected a statement, found {}", describe_tok(other))),
        };
        match kw.as_str() {
            "CREATE" => self.create(),
            "INSERT" => self.insert(),
            "SELECT" => self.select(),
            other => Err(format!("unsupported statement: {other}")),
        }
    }

    fn create(&mut self) -> Result<Stmt, String> {
        self.eat_kw("CREATE")?;
        self.eat_kw("TABLE")?;
        let table = self.ident()?;
        self.eat_sym('(')?;
        let mut cols = Vec::new();
        loop {
            let col = self.ident()?;
            cols.push(col);
            // Consume the column type (one or more tokens) up to `,` or `)`,
            // including a parenthesised size like VARCHAR(10).
            let mut depth = 0i32;
            loop {
                match self.peek() {
                    Some(Tok::Sym('(')) => {
                        depth += 1;
                        self.pos += 1;
                    }
                    Some(Tok::Sym(')')) if depth > 0 => {
                        depth -= 1;
                        self.pos += 1;
                    }
                    Some(Tok::Sym(')')) | Some(Tok::Sym(',')) if depth == 0 => break,
                    Some(_) => {
                        self.pos += 1;
                    }
                    None => return Err("unterminated CREATE TABLE column list".to_string()),
                }
            }
            if self.peek_is_sym(',') {
                self.pos += 1;
                continue;
            }
            break;
        }
        self.eat_sym(')')?;
        Ok(Stmt::Create { table, cols })
    }

    fn insert(&mut self) -> Result<Stmt, String> {
        self.eat_kw("INSERT")?;
        self.eat_kw("INTO")?;
        let table = self.ident()?;
        let cols = if self.peek_is_sym('(') {
            self.pos += 1;
            let mut c = Vec::new();
            loop {
                c.push(self.ident()?);
                if self.peek_is_sym(',') {
                    self.pos += 1;
                    continue;
                }
                break;
            }
            self.eat_sym(')')?;
            Some(c)
        } else {
            None
        };
        self.eat_kw("VALUES")?;
        let mut rows = Vec::new();
        loop {
            self.eat_sym('(')?;
            let mut row = Vec::new();
            loop {
                row.push(self.value()?);
                if self.peek_is_sym(',') {
                    self.pos += 1;
                    continue;
                }
                break;
            }
            self.eat_sym(')')?;
            rows.push(row);
            if self.peek_is_sym(',') {
                self.pos += 1;
                continue;
            }
            break;
        }
        Ok(Stmt::Insert { table, cols, rows })
    }

    fn select(&mut self) -> Result<Stmt, String> {
        self.eat_kw("SELECT")?;
        let proj = if self.peek_is_sym('*') {
            self.pos += 1;
            Proj::Star
        } else {
            let mut cols = Vec::new();
            loop {
                cols.push(self.ident()?);
                if self.peek_is_sym(',') {
                    self.pos += 1;
                    continue;
                }
                break;
            }
            Proj::Cols(cols)
        };
        self.eat_kw("FROM")?;
        let table = self.ident()?;
        let filter = if matches!(self.peek(), Some(Tok::Word(w)) if w.eq_ignore_ascii_case("WHERE")) {
            self.pos += 1;
            let col = self.ident()?;
            self.eat_sym('=')?;
            let val = self.value()?;
            Some((col, val))
        } else {
            None
        };
        Ok(Stmt::Select { table, proj, filter })
    }
}

fn describe_tok(t: Option<&Tok>) -> String {
    match t {
        Some(Tok::Word(w)) => format!("`{w}`"),
        Some(Tok::Num(n)) => format!("`{n}`"),
        Some(Tok::Str(s)) => format!("'{s}'"),
        Some(Tok::Sym(c)) => format!("`{c}`"),
        None => "end of input".to_string(),
    }
}

// ── engine ──────────────────────────────────────────────────────────────────

struct Table {
    cols: Vec<String>,
    rows: Vec<Vec<Value>>,
}

#[derive(Default)]
struct Db {
    tables: HashMap<String, Table>,
}

impl Db {
    fn col_index(table: &Table, col: &str) -> Result<usize, String> {
        table
            .cols
            .iter()
            .position(|c| c.eq_ignore_ascii_case(col))
            .ok_or_else(|| format!("no such column: {col}"))
    }

    fn exec(&mut self, stmt: Stmt) -> Result<Option<Vec<Vec<Value>>>, String> {
        match stmt {
            Stmt::Create { table, cols } => {
                if self.tables.contains_key(&table) {
                    return Err(format!("table already exists: {table}"));
                }
                self.tables.insert(table, Table { cols, rows: Vec::new() });
                Ok(None)
            }
            Stmt::Insert { table, cols, rows } => {
                let t = self
                    .tables
                    .get_mut(&table)
                    .ok_or_else(|| format!("no such table: {table}"))?;
                // Map each VALUES row to the table's column order.
                let order: Vec<usize> = match &cols {
                    Some(names) => {
                        let mut idx = Vec::with_capacity(names.len());
                        for n in names {
                            idx.push(
                                t.cols
                                    .iter()
                                    .position(|c| c.eq_ignore_ascii_case(n))
                                    .ok_or_else(|| format!("no such column: {n}"))?,
                            );
                        }
                        idx
                    }
                    None => (0..t.cols.len()).collect(),
                };
                for row in rows {
                    if row.len() != order.len() {
                        return Err(format!(
                            "INSERT column/value count mismatch: {} values for {} columns",
                            row.len(),
                            order.len()
                        ));
                    }
                    if t.rows.len() >= MAX_ROWS {
                        return Err("row cap exceeded".to_string());
                    }
                    let mut full = vec![Value::Int(0); t.cols.len()];
                    for (slot, v) in order.iter().zip(row.into_iter()) {
                        full[*slot] = v;
                    }
                    t.rows.push(full);
                }
                Ok(None)
            }
            Stmt::Select { table, proj, filter } => {
                let t = self
                    .tables
                    .get(&table)
                    .ok_or_else(|| format!("no such table: {table}"))?;
                let filt = match &filter {
                    Some((col, val)) => Some((Self::col_index(t, col)?, val.clone())),
                    None => None,
                };
                let proj_idx: Vec<usize> = match &proj {
                    Proj::Star => (0..t.cols.len()).collect(),
                    Proj::Cols(names) => {
                        let mut idx = Vec::with_capacity(names.len());
                        for n in names {
                            idx.push(Self::col_index(t, n)?);
                        }
                        idx
                    }
                };
                let mut out = Vec::new();
                for row in &t.rows {
                    if let Some((ci, ref want)) = filt {
                        if &row[ci] != want {
                            continue;
                        }
                    }
                    out.push(proj_idx.iter().map(|i| row[*i].clone()).collect());
                }
                Ok(Some(out))
            }
        }
    }
}

fn to_json(rows: &[Vec<Value>]) -> String {
    let mut s = String::from("[");
    for (i, row) in rows.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('[');
        for (j, v) in row.iter().enumerate() {
            if j > 0 {
                s.push(',');
            }
            match v {
                Value::Int(n) => s.push_str(&n.to_string()),
                Value::Str(t) => {
                    s.push('"');
                    for ch in t.chars() {
                        match ch {
                            '"' | '\\' => {
                                s.push('\\');
                                s.push(ch);
                            }
                            '\n' => s.push_str("\\n"),
                            '\t' => s.push_str("\\t"),
                            '\r' => s.push_str("\\r"),
                            _ => s.push(ch),
                        }
                    }
                    s.push('"');
                }
            }
        }
        s.push(']');
    }
    s.push(']');
    s
}

/// Tokenize → parse → execute a (multi-statement) SQL string over a fresh
/// in-memory DB; return the JSON rows of the LAST `SELECT` (or `[]` if none).
fn run_sql(sql: &str) -> Result<String, String> {
    if sql.len() > MAX_SQL_BYTES {
        return Err("query too large".to_string());
    }
    let toks = tokenize(sql)?;
    let stmts = Parser::new(toks).parse_all()?;
    if stmts.is_empty() {
        return Err("empty query".to_string());
    }
    let mut db = Db::default();
    let mut last: Option<Vec<Vec<Value>>> = None;
    for stmt in stmts {
        if let Some(rows) = db.exec(stmt)? {
            last = Some(rows);
        }
    }
    Ok(to_json(&last.unwrap_or_default()))
}

// ── tool-exports ────────────────────────────────────────────────────────────

struct DbTool;

impl Guest for DbTool {
    fn describe() -> ToolDescription {
        ToolDescription {
            description: "in-wasm SQL tool: runs CREATE TABLE / INSERT / SELECT over an \
                          in-memory engine; returns JSON rows"
                .to_string(),
            methods: vec![MethodInfo {
                name: "query".to_string(),
                description: Some(
                    "execute a SQL string (semicolon-separated statements); the params \
                     are RAW UTF-8 SQL text and the result is the final SELECT's rows as \
                     a JSON array of arrays"
                        .to_string(),
                ),
                // No input/output JSON schema: the input is RAW SQL text bytes (not a
                // JSON document), so declaring a schema would make the host's L2
                // input-schema validator reject the raw SQL as "not valid JSON" before
                // the component runs (mirrors the echo tool, which also declares None).
                input_schema: None,
                output_schema: None,
                // Not idempotent: a query may CREATE/INSERT (mutating) within its
                // own ephemeral engine.
                idempotent: Some(false),
            }],
        }
    }

    fn execute(method: String, params: Vec<u8>) -> Result<Vec<u8>, String> {
        match method.as_str() {
            "query" => {
                let sql = String::from_utf8(params)
                    .map_err(|_| "params are not valid UTF-8 SQL".to_string())?;
                run_sql(&sql).map(String::into_bytes)
            }
            other => Err(format!("method-not-found: {other}")),
        }
    }
}

export!(DbTool with_types_in crate);
