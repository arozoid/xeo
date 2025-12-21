use clap::Parser;
use colored::*;
use std::path::PathBuf;
use std::fs;
use std::io::Write;
use std::io;
use std::env;
use std::collections::HashMap;
use std::path::Path;

fn get_xeon_dir() -> PathBuf {
    #[cfg(windows)]
    let mut path = PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default());
    
    #[cfg(unix)]
    let mut path = PathBuf::from(std::env::var("HOME").unwrap_or_default());

    path.push(".xeon");
    path
}

#[derive(Parser, Debug)]
#[command(name = "xeo", about = ABOUT, version = VERSION, disable_version_flag = true)]
struct Cli {
  /// reverses .xeo operations
  #[arg(short, long)]
  reverse: bool,
  
  /// prints current .xeo version
  #[arg(short = 'V', long)]
  version: bool,
  /// enable verbose debug output
  #[arg(short, long)]
  verbose: bool,
  
  #[arg(required = false)]
  path: Option<String>,

  /// Everything after the script name gets passed to the script
  #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
  script_args: Vec<String>,
}

static VERSION: &str = env!("CARGO_PKG_VERSION");
static ABOUT: &str = "\u{1b}[0;32mthe .xeo scripting lang\u{1b}[0m";

#[derive(Debug)]
enum Token {
    Command(String),
    StringLiteral(String),
    Variable(String),
    // could add Symbol(char) later if needed
}

// helper functions
fn get_current_path() -> String {
    env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "Unknown".to_string())
}

fn change_path(target: &PathBuf) -> Result<PathBuf, std::io::Error> {
    env::set_current_dir(target)?;
    // Return the absolute version so you can log exactly where you are
    env::current_dir()
}

// lexer functions
fn lex_line(line: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();

    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }

        if ch == '"' {
            // string literal
            chars.next(); // consume opening quote
            let mut content = String::new();
            while let Some(c) = chars.next() {
                if c == '"' {
                    break;
                }
                content.push(c);
            }
            tokens.push(Token::StringLiteral(content));
            continue;
        }

        if ch == '$' {
            // variable
            chars.next(); // consume $
            let mut ident = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_alphanumeric() || c == '_' {
                    ident.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            tokens.push(Token::Variable(format!("${}", ident)));
            continue;
        }

        if ch == '+' {
            chars.next();
            tokens.push(Token::Command("+".to_string()));
            continue;
        }

        // plain command/word (e.g., as, repeat, print, numbers)
        let mut word = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() || c == '+' || c == '$' || c == '"' {
                break;
            }
            word.push(c);
            chars.next();
        }
        if !word.is_empty() {
            tokens.push(Token::Command(word));
        }
    }

    tokens
}

fn lex_lines(lines: &str) -> Vec<Vec<Token>> {
    lines
        .lines()
        .filter(|l| !l.trim().is_empty()) // skip blank lines
        .map(|l| lex_line(l))
        .collect()
}

// parser functions
#[derive(Debug, Clone)]
enum ASTNodeKind {
    Command { name: String, args: Vec<String> },
    Repeat { times: String, var: Option<String>, body: Vec<ASTNode> },
    Func { name: String, params: Vec<String>, body: Vec<ASTNode> },
    If { condition: String, body: Vec<ASTNode>, else_body: Vec<ASTNode> },
}

#[derive(Debug, Clone)]
struct ASTNode {
    kind: ASTNodeKind,
    line_number: usize,
}

fn tokens_to_args(tokens: &[Token]) -> Vec<String> {
    tokens.iter().filter_map(|t| match t {
        Token::StringLiteral(s) => Some(s.clone()),
        Token::Variable(v) => Some(v.clone()),
        Token::Command(c) if c != "|" => Some(c.clone()),
        _ => None,
    }).collect()
}

fn parse_block(lines: &[(usize, Vec<Token>)], start_idx: usize, end_idx: usize) -> (Vec<ASTNode>, usize) {
    let mut ast = Vec::new();
    let mut i = start_idx;

    while i < end_idx {
        let (line_number, tokens) = &lines[i];
        match tokens.first() {
            Some(Token::Command(cmd)) if cmd == "end" => {
                // End of block, return what we've parsed so far
                return (ast, i + 1);
            }
            Some(Token::Command(cmd)) if cmd == "repeat" => {
                // determine repeat count (accept string, variable, or plain numeric command)
                let times = tokens.get(1).map(|t| match t {
                    Token::StringLiteral(s) => s.clone(),
                    Token::Variable(v) => v.clone(),
                    Token::Command(c) => c.clone(),
                }).unwrap_or_else(|| "1".to_string());

                // determine optional loop variable: syntax `repeat <n> as $var`
                let mut var_name = String::new();
                if tokens.len() >= 4 {
                    if let Token::Command(as_kw) = &tokens[2] {
                        if as_kw == "as" {
                            if let Some(t) = tokens.get(3) {
                                match t {
                                    Token::Variable(v) => var_name = v.clone(),
                                    Token::StringLiteral(s) => var_name = s.clone(),
                                    Token::Command(c) => var_name = c.clone(),
                                }
                            }
                        }
                    }
                }

                let (body, consumed) = parse_block(lines, i+1, end_idx);
                ast.push(ASTNode {
                    kind: ASTNodeKind::Repeat { times, var: if var_name.is_empty() { None } else { Some(var_name) }, body },
                    line_number: *line_number,
                });
                i = consumed;
                continue;
            }
            Some(Token::Command(cmd)) if cmd == "if" => {
                // extract full condition expression (all tokens after `if`)
                let cond_parts: Vec<String> = tokens.iter().skip(1).filter_map(|t| match t {
                    Token::StringLiteral(s) => Some(s.clone()),
                    Token::Variable(v) => Some(v.clone()),
                    Token::Command(c) => Some(c.clone()),
                }).collect();
                let condition = cond_parts.join(" ");

                // parse body until 'else' or 'end'
                let mut body: Vec<ASTNode> = Vec::new();
                let mut else_body: Vec<ASTNode> = Vec::new();
                let mut j = i + 1;
                while j < end_idx {
                    let (ln2, toks2) = &lines[j];
                    match toks2.first() {
                        Some(Token::Command(c2)) if c2 == "end" => {
                            j += 1; // consume 'end'
                            break;
                        }
                        Some(Token::Command(c2)) if c2 == "else" => {
                            // support `else if <cond>` on the same line
                            if toks2.len() >= 2 {
                                if let Token::Command(next) = &toks2[1] {
                                    if next == "if" {
                                        // build condition from remaining tokens on this line
                                        let cond_parts: Vec<String> = toks2.iter().skip(2).filter_map(|t| match t {
                                            Token::StringLiteral(s) => Some(s.clone()),
                                            Token::Variable(v) => Some(v.clone()),
                                            Token::Command(c) => Some(c.clone()),
                                        }).collect();
                                        let cond2 = cond_parts.join(" ");

                                        // parse body for this else-if until next `else` or `end` at same level
                                        let mut nested_body: Vec<ASTNode> = Vec::new();
                                        let mut k = j + 1;
                                        while k < end_idx {
                                            let (ln3, toks3) = &lines[k];
                                            match toks3.first() {
                                                Some(Token::Command(x)) if x == "end" || x == "else" => break,
                                                Some(Token::Command(x)) if x == "repeat" || x == "func" || x == "if" => {
                                                    let (nested, consumed) = parse_block(lines, k, end_idx);
                                                    nested_body.extend(nested);
                                                    k = consumed;
                                                    continue;
                                                }
                                                Some(Token::Command(_)) => {
                                                    nested_body.push(ASTNode {
                                                        kind: ASTNodeKind::Command { name: tokens_to_args(&toks3)[0].clone(), args: tokens_to_args(&toks3)[1..].to_vec() },
                                                        line_number: *ln3,
                                                    });
                                                }
                                                Some(&Token::StringLiteral(_)) | Some(&Token::Variable(_)) => todo!(),
                                                None => {},
                                            }
                                            k += 1;
                                        }

                                        // push the else-if as an If node inside else_body
                                        else_body.push(ASTNode {
                                            kind: ASTNodeKind::If { condition: cond2, body: nested_body, else_body: Vec::new() },
                                            line_number: *ln2,
                                        });

                                        // continue parsing from the sentinel (do not consume it here)
                                        j = k;
                                        continue;
                                    }
                                }
                            }

                            // normal `else` (not an `else if`) — parse until matching 'end'
                            let (ebody, consumed) = parse_block(lines, j+1, end_idx);
                            else_body = ebody;
                            j = consumed;
                            break;
                        }
                        Some(Token::Command(c2)) if c2 == "repeat" || c2 == "func" || c2 == "if" => {
                            // nested block: delegate to parse_block starting at this line
                            let (nested, consumed) = parse_block(lines, j, end_idx);
                            body.extend(nested);
                            j = consumed;
                            continue;
                        }
                        Some(Token::Command(_)) => {
                            // simple command line inside if body
                            body.push(ASTNode {
                                kind: ASTNodeKind::Command { name: tokens_to_args(&toks2)[0].clone(), args: tokens_to_args(&toks2)[1..].to_vec() },
                                line_number: *ln2,
                            });
                        }
                        Some(&Token::StringLiteral(_)) | Some(&Token::Variable(_)) => todo!(),
                        None => {},
                    }
                    j += 1;
                }

                ast.push(ASTNode {
                    kind: ASTNodeKind::If { condition, body, else_body },
                    line_number: *line_number,
                });
                i = j;
                continue;
            }
            Some(Token::Command(cmd)) if cmd == "func" => {
                // collect name and optional parameter names from the func header
                let parts = tokens_to_args(&tokens);
                // parts[0] == "func" normally
                let name = parts.get(1).cloned().unwrap_or_else(|| "unnamed".to_string());
                let params = if parts.len() > 2 { parts[2..].to_vec() } else { Vec::new() };

                let (body, consumed) = parse_block(lines, i+1, end_idx);
                ast.push(ASTNode {
                    kind: ASTNodeKind::Func { name, params, body },
                    line_number: *line_number,
                });
                i = consumed;
                continue;
            }
            Some(Token::Command(_)) => {
                ast.push(ASTNode {
                    kind: ASTNodeKind::Command { name: tokens_to_args(&tokens)[0].clone(), args: tokens_to_args(&tokens)[1..].to_vec() },
                    line_number: *line_number,
                });
            }
            Some(&Token::StringLiteral(_)) | Some(&Token::Variable(_)) => todo!(),
            None => {},
        }
        i += 1;
    }

    (ast, i)
}

fn parse_tokens(lines: Vec<Vec<Token>>) -> Vec<ASTNode> {
    let numbered_lines: Vec<(usize, Vec<Token>)> = lines.into_iter().enumerate().map(|(i,t)| (i+1, t)).collect();
    let (ast, _) = parse_block(&numbered_lines, 0, numbered_lines.len());
    ast
}

// interpreter functions
struct Context {
    variables: HashMap<String, String>,
    line_map: HashMap<usize, *const ASTNode>, // line number -> AST node
    // function name -> (params, body)
    functions: HashMap<String, (Vec<String>, Vec<ASTNode>)>,
    reverse_ops: Vec<ReverseOp>,
    reverse_mode: bool,
    verbose: bool,
    script_dir: Option<PathBuf>,
    script_args: Vec<String>,
}

impl Context {
    fn new() -> Self {
        Self { variables: HashMap::new(), line_map: HashMap::new(), functions: HashMap::new(), reverse_ops: Vec::new(), reverse_mode: false, verbose: false, script_dir: None, script_args: Vec::new() }
    }
}

fn verbose_log(ctx: &Context, msg: &str) {
    if ctx.verbose {
        println!("{} {}", "[xeo] dbg:".cyan(), msg);
    }
}

#[derive(Debug, Clone)]
enum ReverseOp {
    Delete(String), // path
    Move { src: String, dest: String },
    Restore { backup: String, original: String },
    Chmod { path: String, mode: u32 },
    Chdir { from: String, to: String },
}

fn interpolate(s: &str, ctx: &Context) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' {
            // collect identifier
            let mut ident = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_alphanumeric() || c == '_' {
                    ident.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            if !ident.is_empty() {
                let key = format!("${}", ident);
                if let Some(val) = ctx.variables.get(&key) {
                    out.push_str(val);
                }
            } else {
                out.push('$');
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn report_error(msg: &str) {
    eprintln!("{} {}", "[xeo] err:".red(), msg);
}

fn prepare_condition(cond: &str, ctx: &Context) -> String {
    let ops = ["==","!=","<=",">=","<",">","&&","||","(",")","+","-","*","/","%"];
    let mut out_parts: Vec<String> = Vec::new();
    for tok in cond.split_whitespace() {
        if tok.starts_with('$') {
            if let Some(val) = ctx.variables.get(tok) {
                // numeric or boolean should be unquoted
                if val.parse::<f64>().is_ok() || val == "true" || val == "false" {
                    out_parts.push(val.clone());
                } else {
                    let esc = val.replace('"', "\\\"");
                    out_parts.push(format!("\"{}\"", esc));
                }
            } else {
                // unknown variable -> treat as empty string
                out_parts.push("\"\"".to_string());
            }
        } else if tok.starts_with('"') && tok.ends_with('"') {
            out_parts.push(tok.to_string());
        } else if ops.contains(&tok) {
            out_parts.push(tok.to_string());
        } else if tok.parse::<f64>().is_ok() || tok == "true" || tok == "false" {
            out_parts.push(tok.to_string());
        } else {
            // treat as literal string
            let esc = tok.replace('"', "\\\"");
            out_parts.push(format!("\"{}\"", esc));
        }
    }
    out_parts.join(" ")
}

fn ensure_recycle_dir(_ctx: &Context) -> Option<PathBuf> {
    // place recycle directory under ~/.xeon to centralize backups
    let mut dir = get_xeon_dir();
    dir.push(".xeo_recycle");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        report_error(&format!("could not create recycle dir: {}", e));
        return None;
    }
    Some(dir)
}

fn make_backup(ctx: &Context, orig: &str) -> Option<String> {
    let recycle = ensure_recycle_dir(ctx)?;
    let basename = PathBuf::from(&orig)
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "item".to_string());
    
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let backup_name = format!("{}_{}", ts, basename);
    let backup_path = recycle.join(backup_name);
    let backup_str = backup_path.to_string_lossy().to_string();

    // ONLY COPY. Do not rename, do not remove_file.
    if let Ok(meta) = std::fs::metadata(orig) {
        if meta.is_file() {
            if std::fs::copy(orig, &backup_str).is_ok() {
                if ctx.verbose {
                    verbose_log(ctx, &format!("make_backup backed up {} to {}", orig, backup_str));
                }
                return Some(backup_str);
            }
        } else if meta.is_dir() {
            report_error(&format!("cannot backup directory {}", orig));
            return None;
        }
    }
    None
}

fn serialize_revlog(path: &PathBuf, ops: &[ReverseOp]) {
    let mut s = String::new();
    for op in ops {
        match op {
            ReverseOp::Delete(p) => s.push_str(&format!("DELETE\t{}\n", p)),
            ReverseOp::Move { src, dest } => s.push_str(&format!("MOVE\t{}\t{}\n", src, dest)),
            ReverseOp::Restore { backup, original } => s.push_str(&format!("RESTORE\t{}\t{}\n", backup, original)),
            ReverseOp::Chmod { path, mode } => s.push_str(&format!("CHMOD\t{}\t{}\n", path, mode)),
            ReverseOp::Chdir { from, to } => s.push_str(&format!("CHDIR\t{}\t{}\n", from, to)),
        }
    }
    if let Err(e) = std::fs::write(path, s) {
        report_error(&format!("failed to write revlog {}: {}", path.display(), e));
    }
}

fn deserialize_revlog(path: &PathBuf) -> Vec<ReverseOp> {
    let mut out = Vec::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            match parts.get(0).map(|s| *s) {
                Some("DELETE") => { if let Some(p) = parts.get(1) { out.push(ReverseOp::Delete(p.to_string())); } }
                Some("MOVE") => { if parts.len() >= 3 { out.push(ReverseOp::Move { src: parts[1].to_string(), dest: parts[2].to_string() }); } }
                Some("RESTORE") => { if parts.len() >= 3 { out.push(ReverseOp::Restore { backup: parts[1].to_string(), original: parts[2].to_string() }); } }
                Some("CHMOD") => { if parts.len() >= 3 { if let Ok(m) = parts[2].parse::<u32>() { out.push(ReverseOp::Chmod { path: parts[1].to_string(), mode: m }); } } }
                Some("CHDIR") => { if parts.len() >= 3 { out.push(ReverseOp::Chdir { from: parts[1].to_string(), to: parts[2].to_string() }); } }
                _ => {}
            }
        }
    }
    out
}

fn execute_reverse_ops(mut ops: Vec<ReverseOp>, base_dir: Option<PathBuf>, verbose: bool) {
    // execute in reverse order
    ops.reverse();
    for op in ops {
        match op {
            ReverseOp::Delete(p) => {
                if verbose { println!("{} DELETE {}", "[xeo] dbg:".cyan(), p); }
                let _ = if std::fs::metadata(&p).map(|m| m.is_dir()).unwrap_or(false) { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
            }
            ReverseOp::Move { src, dest } => {
                if verbose { println!("{} MOVE {} -> {}", "[xeo] dbg:".cyan(), src, dest); }
                let _ = std::fs::rename(&src, &dest);
            }
            ReverseOp::Restore { backup, original } => {
                // If original is relative, resolve against base_dir (script start dir) if provided
                let orig_path = if Path::new(&original).is_absolute() {
                    PathBuf::from(&original)
                } else if let Some(b) = base_dir.as_ref() {
                    b.join(&original)
                } else {
                    PathBuf::from(&original)
                };
                if verbose { println!("{} RESTORE {} -> {}", "[xeo] dbg:".cyan(), backup, orig_path.display()); }
                let _ = std::fs::rename(&backup, &orig_path);
            }
            ReverseOp::Chmod { path, mode } => {
                if verbose { println!("{} CHMOD {} -> {}", "[xeo] dbg:".cyan(), path, mode); }
                #[cfg(unix)] {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
                }
                #[cfg(not(unix))] {
                    // On Windows we stored previous readonly as 0/1 in mode. Restore it.
                    let prev_readonly = mode != 0;
                    if let Ok(meta) = std::fs::metadata(&path) {
                        let mut perms = meta.permissions();
                        perms.set_readonly(prev_readonly);
                        let _ = std::fs::set_permissions(&path, perms);
                    }
                }
            }
            ReverseOp::Chdir { from, to: _ } => {
                if verbose { println!("{} CHDIR -> {}", "[xeo] dbg:".cyan(), from); }
                if let Err(e) = std::env::set_current_dir(&from) {
                    report_error(&format!("failed to chdir during reverse to {}: {}", from, e));
                }
            }
        }
    }
}

fn execute_ast(ast: &[ASTNode], ctx: &mut Context) {
    // build line map for go
    for node in ast {
        ctx.line_map.insert(node.line_number, node as *const ASTNode);
    }

    // register function definitions so `run` can find them
    for node in ast {
        if let ASTNodeKind::Func { name, params, body } = &node.kind {
            ctx.functions.insert(name.clone(), (params.clone(), body.clone()));
        }
    }

    let mut pc = 0;
    while pc < ast.len() {
        if let Some(jump) = execute_node(&ast[pc], ctx) {
            // handle go
            if let Some(&target_ptr) = ctx.line_map.get(&jump) {
                // find index of target node
                pc = ast.iter().position(|n| n as *const _ == target_ptr).unwrap_or(pc+1);
                continue;
            }
        }
        pc += 1;
    }
}

fn execute_node(node: &ASTNode, ctx: &mut Context) -> Option<usize> {
    match &node.kind {
        ASTNodeKind::Command { name, args } => match name.as_str() {
            "print" => {
                for arg in args {
                    let rendered = interpolate(arg, ctx);
                    print!("{}", rendered);
                }
                println!();
            }
            "string" => {
                if args.is_empty() {
                    // nothing to do
                } else {
                    // look for `as` syntax: parts before `as` are the expression, token after `as` is the variable
                    let as_idx = args.iter().position(|s| s == "as");

                    let (expr_parts, var_name_opt) = if let Some(i) = as_idx {
                        (args[..i].to_vec(), args.get(i+1).cloned())
                    } else if args.len() >= 2 && args.last().map_or(false, |s| s.starts_with('$')) {
                        // support: string <expr...> $var
                        (args[..args.len()-1].to_vec(), args.last().cloned())
                    } else if args.len() >= 2 {
                        // backward compatible: string <value> <var>
                        (vec![args[0].clone()], args.get(1).cloned())
                    } else {
                        (args.clone(), None)
                    };

                    // evaluate expression parts, skipping '+' tokens and interpolating variables inside parts
                    let mut evaluated_parts: Vec<String> = Vec::new();
                    let mut i = 0;
                    while i < expr_parts.len() {
                        if expr_parts[i] == "+" {
                            i += 1;
                            continue;
                        }
                        evaluated_parts.push(interpolate(&expr_parts[i], ctx));
                        i += 1;
                    }

                    let value = evaluated_parts.join("");
                    if let Some(var_name) = var_name_opt {
                        // Support indirection: `string "..." as $$var` should set the
                        // variable whose name is the value of `$var` (i.e. create `$<value>`).
                        // Tokenization may produce two variable tokens for `$$var` ("$" then "$var").
                        if var_name.starts_with("$$") {
                            // e.g. var_name == "$$var" -> lookup $var
                            let inner = &var_name[2..];
                            let lookup_key = format!("${}", inner);
                            if let Some(target) = ctx.variables.get(&lookup_key) {
                                let target_key = format!("${}", target);
                                ctx.variables.insert(target_key, value);
                            } else {
                                report_error(&format!("indirection failed: {} not set", lookup_key));
                            }
                        } else if var_name == "$" {
                            // tokenization case: `$$var` -> tokens ["$", "$var"] so var_name_opt == "$"
                            if let Some(as_idx) = args.iter().position(|s| s == "as") {
                                if as_idx + 2 < args.len() {
                                    let next = args[as_idx + 2].clone();
                                    if next.starts_with('$') {
                                        let lookup_key = next;
                                        if let Some(target) = ctx.variables.get(&lookup_key) {
                                            let target_key = format!("${}", target);
                                            ctx.variables.insert(target_key, value);
                                        } else {
                                            report_error(&format!("indirection failed: {} not set", lookup_key));
                                        }
                                    } else {
                                        ctx.variables.insert(var_name, value);
                                    }
                                } else {
                                    ctx.variables.insert(var_name, value);
                                }
                            } else {
                                ctx.variables.insert(var_name, value);
                            }
                        } else {
                            // normal case: set variable directly (var_name includes leading $)
                            ctx.variables.insert(var_name, value);
                        }
                    }
                }
            }
            "calc" => {
                if let Some(idx) = args.iter().position(|s| s == "as") {
                    // 1. get the math parts and interpolate ($var -> 10)
                    let eval_parts: Vec<String> = args[..idx]
                        .iter()
                        .map(|p| interpolate(p, &ctx))
                        .collect();
                    let calc_string = eval_parts.join(" ");

                    // 2. actually do the math
                    match evalexpr::eval(&calc_string) {
                        Ok(value) => {
                            // 3. safely get the variable name after 'as'
                            if let Some(var_name) = args.get(idx + 1) {
                                ctx.variables.insert(var_name.clone(), value.to_string());
                            }
                        }
                        Err(e) => report_error(&format!("calc error: {}", e)),
                    }
                } else {
                    report_error("usage: calc <expression> as <variable>");
                }
            }
            "ask" => {
                // Syntax: ask $var "What is your name? "
                if let (Some(_var), Some(prompt_text)) = (args.get(0), args.get(1)) {
                    let prompt = interpolate(prompt_text, ctx);
                    print!("{}", prompt);
                } else if let Some(_var) = args.get(0) {
                    print!("> "); // Default prompt
                }

                io::stdout().flush().ok(); // Shorthand for "try to flush, ignore errors"
                
                let mut input = String::new();
                if io::stdin().read_line(&mut input).is_ok() {
                    ctx.variables.insert(args[0].clone(), input.trim().to_string());
                }
            }
            "go" => {
                if let Some(target_line) = args.get(0) {
                    if let Ok(line) = target_line.parse::<usize>() {
                        return Some(line);
                    }
                }
            }
            "dir" => {
                if let Some(p) = args.get(0) {
                    let path = interpolate(p, ctx);
                    // compute canonical absolute forms for prev and new paths
                    let prev_abs = std::env::current_dir()
                        .ok()
                        .and_then(|p| std::fs::canonicalize(&p).ok())
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| get_current_path());

                    let new_abs = {
                        let candidate = if Path::new(&path).is_absolute() {
                            PathBuf::from(&path)
                        } else {
                            std::env::current_dir().map(|cwd| cwd.join(&path)).unwrap_or_else(|_| PathBuf::from(&path))
                        };
                        std::fs::canonicalize(&candidate).map(|p| p.display().to_string()).unwrap_or_else(|_| candidate.display().to_string())
                    };

                    if ctx.verbose {
                        verbose_log(ctx, &format!("chdir: {} -> {}", prev_abs, new_abs));
                    }

                    match std::env::set_current_dir(&path) {
                        Ok(_) => {
                            if ctx.verbose {
                                if let Ok(cwd) = std::env::current_dir() {
                                    verbose_log(ctx, &format!("cwd now: {}", cwd.display()));
                                }
                            }
                            if !ctx.reverse_mode {
                                // record chdir as from previous abs -> new abs
                                ctx.reverse_ops.push(ReverseOp::Chdir { from: prev_abs.clone(), to: new_abs.clone() });
                            }
                        }
                        Err(e) => report_error(&format!("dir error: {}", e)),
                    }
                }
            }
            "mkdir" => {
                if let Some(p) = args.get(0) {
                    let path = interpolate(p, ctx);
                    match std::fs::create_dir_all(&path) {
                        Ok(_) => {
                            if ctx.verbose {
                                verbose_log(ctx, &format!("mkdir created: {}", path));
                            }
                            if !ctx.reverse_mode {
                                let abs = if Path::new(&path).is_absolute() { path.clone() } else { std::env::current_dir().map(|cwd| cwd.join(&path).display().to_string()).unwrap_or(path.clone()) };
                                ctx.reverse_ops.push(ReverseOp::Delete(abs));
                            }
                        }
                        Err(e) => report_error(&format!("mkdir error: {}", e)),
                    }
                }
            }
            "make" => {
                if let Some(p) = args.get(0) {
                    // 1. Get the name (Handle variables like $name)
                    let file_name = interpolate(p, ctx);

                    // 2. Create it exactly as provided
                    // compute an absolute path for logging / reverse-op bookkeeping
                    let abs = if Path::new(&file_name).is_absolute() {
                        file_name.clone()
                    } else {
                        std::env::current_dir().map(|cwd| cwd.join(&file_name).display().to_string()).unwrap_or(file_name.clone())
                    };

                    // ensure parent directories exist (defensive)
                    let abs_pathbuf = PathBuf::from(&abs);
                    if let Some(parent) = abs_pathbuf.parent() {
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            report_error(&format!("failed to create parent dirs {}: {}", parent.display(), e));
                        }
                    }

                    // create the file using the absolute path and verify
                    match std::fs::OpenOptions::new().create(true).write(true).open(&abs_pathbuf) {
                        Ok(f) => {
                            if let Err(e) = f.sync_all() { verbose_log(ctx, &format!("failed to sync file: {}", e)); }
                            if ctx.verbose {
                                verbose_log(ctx, &format!("make created: {} (abs {})", file_name, abs));
                            }
                            // ensure file exists
                            if std::fs::metadata(&abs_pathbuf).is_err() {
                                report_error(&format!("file created but metadata not found: {}", abs_pathbuf.display()));
                            }
                            // record reverse-op
                            if !ctx.reverse_mode {
                                ctx.reverse_ops.push(ReverseOp::Delete(abs));
                            }
                        }
                        Err(e) => {
                            report_error(&format!("failed to create file {}: {}", abs_pathbuf.display(), e));
                        }
                    }
                }
            }
            "move" => {
                if let (Some(s), Some(d)) = (args.get(0), args.get(1)) {
                    let src = interpolate(s, ctx);
                    let dest = interpolate(d, ctx);
                    // Try direct rename first
                    match std::fs::rename(&src, &dest) {
                        Ok(_) => {
                            if !ctx.reverse_mode {
                                let abs_src = if Path::new(&src).is_absolute() { src.clone() } else { std::env::current_dir().map(|cwd| cwd.join(&src).display().to_string()).unwrap_or(src.clone()) };
                                let abs_dest = if Path::new(&dest).is_absolute() { dest.clone() } else { std::env::current_dir().map(|cwd| cwd.join(&dest).display().to_string()).unwrap_or(dest.clone()) };
                                ctx.reverse_ops.push(ReverseOp::Move { src: abs_dest.clone(), dest: abs_src.clone() });
                            }
                        }
                        Err(e) => {
                            // If both src and dest are directories, move contents of src into dest, then remove src
                            let src_meta = std::fs::metadata(&src).ok();
                            let dest_meta = std::fs::metadata(&dest).ok();
                            if src_meta.as_ref().map(|m| m.is_dir()).unwrap_or(false) && dest_meta.as_ref().map(|m| m.is_dir()).unwrap_or(false) {
                                // iterate entries in src and move into dest
                                if let Ok(entries) = std::fs::read_dir(&src) {
                                    for ent in entries.filter_map(|e| e.ok()) {
                                        let ent_path = ent.path();
                                        if let Some(name) = ent_path.file_name().and_then(|s| s.to_str()) {
                                            let dest_entry = Path::new(&dest).join(name);
                                            let dest_entry_str = dest_entry.display().to_string();
                                            let ent_path_str = ent_path.display().to_string();

                                            // attempt rename; on cross-filesystem, fallback to copy/remove
                                            if std::fs::rename(&ent_path, &dest_entry).is_err() {
                                                // fallback
                                                if let Ok(meta) = std::fs::metadata(&ent_path) {
                                                    if meta.is_dir() {
                                                        // copy dir recursively
                                                        if let Err(e2) = fs_extra::dir::copy(&ent_path, &dest, &fs_extra::dir::CopyOptions::new()) {
                                                            report_error(&format!("move (copy) error for dir {} -> {}: {}", ent_path_str, dest, e2));
                                                            continue;
                                                        }
                                                        // remove original
                                                        if let Err(e2) = std::fs::remove_dir_all(&ent_path) {
                                                            report_error(&format!("failed to remove original dir {}: {}", ent_path_str, e2));
                                                        }
                                                    } else {
                                                        if let Err(e2) = std::fs::copy(&ent_path, &dest_entry) {
                                                            report_error(&format!("move (copy) error for file {} -> {}: {}", ent_path_str, dest_entry_str, e2));
                                                            continue;
                                                        }
                                                        if let Err(e2) = std::fs::remove_file(&ent_path) {
                                                            report_error(&format!("failed to remove original file {}: {}", ent_path_str, e2));
                                                        }
                                                    }
                                                }
                                            }

                                            if !ctx.reverse_mode {
                                                // record reverse move: move dest_entry back to original ent_path
                                                let abs_dest_entry = if Path::new(&dest_entry_str).is_absolute() { dest_entry_str.clone() } else { std::env::current_dir().map(|cwd| cwd.join(&dest_entry_str).display().to_string()).unwrap_or(dest_entry_str.clone()) };
                                                let abs_ent_path = if Path::new(&ent_path_str).is_absolute() { ent_path_str.clone() } else { std::env::current_dir().map(|cwd| cwd.join(&ent_path_str).display().to_string()).unwrap_or(ent_path_str.clone()) };
                                                ctx.reverse_ops.push(ReverseOp::Move { src: abs_dest_entry, dest: abs_ent_path });
                                            }
                                        }
                                    }
                                }

                                // backup (move) the now-empty src directory into recycle so reverse can restore it
                                if !ctx.reverse_mode {
                                    if let Some(backup) = make_backup(ctx, &src) {
                                        ctx.reverse_ops.push(ReverseOp::Restore { backup, original: src.clone() });
                                    }
                                } else {
                                    // during reverse-mode we should remove the empty src if it still exists
                                    let _ = std::fs::remove_dir_all(&src);
                                }
                            } else {
                                report_error(&format!("move error: {} -> {}: {}", src, dest, e));
                            }
                        }
                    }
                }
            }
            "copy" => {
                if let (Some(s), Some(d)) = (args.get(0), args.get(1)) {
                    let src = interpolate(s, ctx);
                    let dest = interpolate(d, ctx);
                    match std::fs::copy(&src, &dest) {
                        Ok(_) => {
                            if !ctx.reverse_mode {
                                let abs_dest = if Path::new(&dest).is_absolute() { dest.clone() } else { std::env::current_dir().map(|cwd| cwd.join(&dest).display().to_string()).unwrap_or(dest.clone()) };
                                // if dest existed before, backup it; otherwise delete dest on reverse
                                ctx.reverse_ops.push(ReverseOp::Delete(abs_dest));
                            }
                        }
                        Err(e) => report_error(&format!("copy error: {} -> {}: {}", src, dest, e)),
                    }
                }
            }
            "delete" => {
                if let Some(p) = args.get(0) {
                    let path = interpolate(p, ctx);
                    // check if it's a dir or file
                    if let Ok(meta) = std::fs::metadata(&path) {
                        if meta.is_dir() {
                            // attempt to move to recycle for restore
                            if !ctx.reverse_mode {
                                if let Some(backup) = make_backup(ctx, &path) {
                                    ctx.reverse_ops.push(ReverseOp::Restore { backup, original: path.clone() });
                                } else {
                                    // fallback to remove
                                    if let Err(e) = std::fs::remove_dir_all(&path) {
                                        report_error(&format!("delete error (dir): {}: {}", path, e));
                                    }
                                }
                            } else {
                                if let Err(e) = std::fs::remove_dir_all(&path) {
                                    report_error(&format!("delete error (dir): {}: {}", path, e));
                                }
                            }
                        } else {
                            if !ctx.reverse_mode {
                                if let Some(backup) = make_backup(ctx, &path) {
                                    ctx.reverse_ops.push(ReverseOp::Restore { backup, original: path.clone() });
                                } else if let Err(e) = std::fs::remove_file(&path) {
                                    report_error(&format!("delete error (file): {}: {}", path, e));
                                }
                            } else {
                                if let Err(e) = std::fs::remove_file(&path) {
                                    report_error(&format!("delete error (file): {}: {}", path, e));
                                }
                            }
                        }
                    }
                }
            }
            "chmod" => {
                if let Some(p) = args.get(0) {
                    let path = interpolate(p, ctx);
                    #[cfg(unix)] {
                        use std::os::unix::fs::PermissionsExt;
                        // default mode to set — keep legacy behaviour
                        let set_mode = 0o755;
                        match std::fs::metadata(&path) {
                            Ok(meta) => {
                                if meta.is_dir() {
                                    // recurse into directory and chmod each entry, recording previous modes
                                    let mut stack: Vec<PathBuf> = vec![PathBuf::from(&path)];
                                    while let Some(curr) = stack.pop() {
                                        if let Ok(m2) = std::fs::metadata(&curr) {
                                            let prev_mode = m2.permissions().mode();
                                            if let Err(e) = std::fs::set_permissions(&curr, std::fs::Permissions::from_mode(set_mode)) {
                                                report_error(&format!("chmod error on {}: {}", curr.display(), e));
                                            } else if !ctx.reverse_mode {
                                                ctx.reverse_ops.push(ReverseOp::Chmod { path: curr.display().to_string(), mode: prev_mode });
                                            }

                                            if m2.is_dir() {
                                                if let Ok(rd) = std::fs::read_dir(&curr) {
                                                    for ent in rd.filter_map(|e| e.ok()) {
                                                        stack.push(ent.path());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    let prev_mode = meta.permissions().mode();
                                    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(set_mode)) {
                                        report_error(&format!("chmod error: {}", e));
                                    } else if !ctx.reverse_mode {
                                        ctx.reverse_ops.push(ReverseOp::Chmod { path: path.clone(), mode: prev_mode });
                                    }
                                }
                            }
                            Err(e) => report_error(&format!("chmod metadata error: {}", e)),
                        }
                    }
                    #[cfg(not(unix))] {
                        // On non-Unix (Windows), emulate chmod by setting the readonly flag based on owner write bit
                        // default mode to set — keep legacy behaviour (treat 0o755 as writable)
                        let set_mode = 0o755;
                        match std::fs::metadata(&path) {
                            Ok(meta) => {
                                if meta.is_dir() {
                                    let mut stack: Vec<PathBuf> = vec![PathBuf::from(&path)];
                                    while let Some(curr) = stack.pop() {
                                        if let Ok(m2) = std::fs::metadata(&curr) {
                                            let prev_readonly = m2.permissions().readonly();
                                            let readonly = (set_mode & 0o200) == 0; // if owner-write not set -> readonly
                                            if let Err(e) = std::fs::set_permissions(&curr, {
                                                let mut perms = m2.permissions();
                                                perms.set_readonly(readonly);
                                                perms
                                            }) {
                                                report_error(&format!("chmod (win) error on {}: {}", curr.display(), e));
                                            } else if !ctx.reverse_mode {
                                                ctx.reverse_ops.push(ReverseOp::Chmod { path: curr.display().to_string(), mode: if prev_readonly { 1 } else { 0 } });
                                            }

                                            if m2.is_dir() {
                                                if let Ok(rd) = std::fs::read_dir(&curr) {
                                                    for ent in rd.filter_map(|e| e.ok()) {
                                                        stack.push(ent.path());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    let prev_readonly = meta.permissions().readonly();
                                    let readonly = (set_mode & 0o200) == 0;
                                    if let Err(e) = std::fs::set_permissions(&path, {
                                        let mut perms = meta.permissions();
                                        perms.set_readonly(readonly);
                                        perms
                                    }) {
                                        report_error(&format!("chmod (win) error: {}", e));
                                    } else if !ctx.reverse_mode {
                                        ctx.reverse_ops.push(ReverseOp::Chmod { path: path.clone(), mode: if prev_readonly { 1 } else { 0 } });
                                    }
                                }
                            }
                            Err(e) => report_error(&format!("chmod metadata error: {}", e)),
                        }
                    }
                }
            }
            "link" => {
                if let (Some(s), Some(d)) = (args.get(0), args.get(1)) {
                    let src = interpolate(s, ctx);
                    let dest = interpolate(d, ctx);
                    #[cfg(unix)] {
                        match std::os::unix::fs::symlink(&src, &dest) {
                            Ok(_) => { if !ctx.reverse_mode { ctx.reverse_ops.push(ReverseOp::Delete(dest.clone())); } }
                            Err(e) => report_error(&format!("link error: {} -> {}: {}", src, dest, e)),
                        }
                    }
                    #[cfg(windows)] {
                        use std::os::windows::fs::{symlink_file, symlink_dir};
                        let res = if let Ok(meta) = std::fs::metadata(&src) {
                            if meta.is_dir() {
                                std::os::windows::fs::symlink_dir(&src, &dest)
                            } else {
                                std::os::windows::fs::symlink_file(&src, &dest)
                            }
                        } else {
                            // If src doesn't exist yet, assume it's a file
                            std::os::windows::fs::symlink_file(&src, &dest)
                        };
                        if let Err(e) = res {
                            report_error(&format!("link error: {} -> {}: {}", src, dest, e));
                        } else if !ctx.reverse_mode {
                            ctx.reverse_ops.push(ReverseOp::Delete(dest.clone()));
                        }
                    }
                }
            }
            "append" => {
                if let (Some(f), Some(t)) = (args.get(0), args.get(1)) {
                    let path = interpolate(f, ctx);
                    let text = interpolate(t, ctx);
                    use std::io::Write;

                    if std::fs::metadata(&path).is_ok() && !ctx.reverse_mode {
                        if let Some(backup) = make_backup(ctx, &path) {
                            ctx.reverse_ops.push(ReverseOp::Restore { backup: backup.clone(), original: path.clone() });
                        }
                    }

                    // Explicitly set append(true) and ensure truncate is NOT active
                    let result = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path);

                    match result {
                        Ok(mut file) => {
                            // Using writeln! adds the text + a newline
                            if let Err(e) = writeln!(file, "{}", text) {
                                report_error(&format!("append error: {}", e));
                            }
                        }
                        Err(e) => report_error(&format!("append error: {}", e)),
                    }
                }
            }
            "replace" => {
                if let (Some(f), Some(t)) = (args.get(0), args.get(1)) {
                    let path = interpolate(f, ctx);
                    let text = interpolate(t, ctx);
                    // backup original before replacing
                    if std::fs::metadata(&path).is_ok() && !ctx.reverse_mode {
                        if let Some(backup) = make_backup(ctx, &path) {
                            ctx.reverse_ops.push(ReverseOp::Restore { backup: backup.clone(), original: path.clone() });
                        }
                    }
                    if let Err(e) = std::fs::write(&path, text) {
                        report_error(&format!("replace error: {}", e));
                    }
                }
            }
            "use" => {
                if let Some(p) = args.get(0) {
                    let path = interpolate(p, ctx);
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        // 1. Convert string to 2D tokens (Lines -> Tokens)
                        let sub_tokens = lex_lines(&content);
                        
                        // 2. Convert 2D tokens to AST
                        let sub_ast = parse_tokens(sub_tokens); 
                        
                        // 3. Execute using the SAME context
                        execute_ast(&sub_ast, ctx);
                    } else {
                        report_error(&format!("use error: could not read file at {}", &path));
                    }
                }
            }
            "run" => {
                if let Some(fname) = args.get(0) {
                    // 1. Get the function entry (params + body)
                    let entry = ctx.functions.get(fname).cloned();

                    if let Some((params, nodes)) = entry {
                        // 2. Map the "run" arguments into named params or positional $1/$2 fallback
                        if !params.is_empty() {
                            for (i, val) in args.iter().skip(1).enumerate() {
                                if let Some(param_name) = params.get(i) {
                                    let clean_val = val.trim_matches('"').to_string();
                                    ctx.variables.insert(param_name.clone(), clean_val);
                                }
                            }
                        } else {
                            for (i, val) in args.iter().skip(1).enumerate() {
                                let pos_name = format!("${}", i + 1); // Creates $1, $2, etc.
                                let clean_val = val.trim_matches('"').to_string();
                                ctx.variables.insert(pos_name, clean_val);
                            }
                        }

                        // 3. Execute function body
                        execute_ast(&nodes, ctx);
                    } else {
                        report_error(&format!("run error: unknown function {}", fname));
                    }
                }
            }
            "wget" => {
                let url = args[0].trim_matches('"');
                let file_path = args[1].trim_matches('"');

                verbose_log(ctx, &format!("downloading: {} -> {}", url, file_path));

                match ureq::get(url).call() {
                    Ok(response) => {
                        // Create the local file
                        match std::fs::File::create(file_path) {
                            Ok(mut file) => {
                                // Stream the body directly to the file
                                let mut reader = response.into_reader();
                                match std::io::copy(&mut reader, &mut file) {
                                    Ok(bytes) => {
                                        verbose_log(ctx, &format!("wrote {} bytes", bytes));
                                    }
                                    Err(e) => report_error(&format!("wget write error: {}", e)),
                                }
                            }
                            Err(e) => report_error(&format!("wget disk error: {}", e)),
                        }
                    }
                    Err(e) => {
                        report_error(&format!("wget failed: {}", e));
                    }
                }
            }
            "fetch" => {
                let url = args[0].trim_matches('"');
                let target_var = args[1].clone(); // keep the $ if that's your style

                match ureq::get(url).call() {
                    Ok(res) => {
                        let text = res.into_string().unwrap_or_else(|_| "ERR_READ_BODY".to_string());
                        verbose_log(ctx, &format!("captured {} bytes", text.len()));
                        ctx.variables.insert(target_var, text);
                    }
                    Err(e) => {
                        report_error(&format!("fetch failed: {}", e));
                    }
                }
            }
            "ext" => {
                if let Some(plugin_name) = args.get(0) {
                    let plugin_name = interpolate(plugin_name, ctx);
                    
                    // Construct path to ~/.xeon/bin
                    let mut exe_path = home::home_dir()
                        .map(|p| p.join(".xeon").join("bin"))
                        .unwrap_or_else(|| std::path::PathBuf::from("."));
                    
                    exe_path.push(&plugin_name);

                    #[cfg(windows)]
                    if exe_path.extension().is_none() {
                        exe_path.set_extension("exe");
                    }

                    if exe_path.exists() {
                        let plugin_args: Vec<String> = args[1..].iter()
                            .map(|a| interpolate(a, ctx))
                            .collect();

                        if ctx.verbose {
                            verbose_log(ctx, &format!("executing extension: {:?}", exe_path));
                        }

                        // Execute and inherit streams
                        let mut cmd = std::process::Command::new(&exe_path);
                        let status = cmd.args(plugin_args)
                            .stdin(std::process::Stdio::inherit())
                            .stdout(std::process::Stdio::inherit())
                            .stderr(std::process::Stdio::inherit())
                            .status();

                        match status {
                            Ok(s) => {
                                // Force a flush of stdout so child output appears before parent continues
                                use std::io::Write;
                                let _ = std::io::stdout().flush();

                                if !s.success() {
                                    if ctx.verbose {
                                        verbose_log(ctx, &format!("extension {} exited with code: {}", plugin_name, s));
                                    }
                                }
                            }
                            Err(e) => report_error(&format!("failed to start {}: {}", plugin_name, e)),
                        }
                    } else {
                        report_error(&format!("binary not found: {:?}", exe_path));
                    }
                } else {
                    report_error("ext requires a plugin name");
                }
            }
            "read" => {
                // Accept: read <path> as $var   OR   read <path> $var   OR   read <path> <var>
                if args.is_empty() {
                    report_error("read requires at least a path and a target variable");
                } else {
                    // determine variable token after optional `as`
                    let var_opt = if let Some(pos) = args.iter().position(|s| s == "as") {
                        args.get(pos + 1).cloned()
                    } else if args.len() >= 2 {
                        args.get(1).cloned()
                    } else {
                        None
                    };

                    if var_opt.is_none() {
                        report_error("read requires a target variable: read <path> as $var");
                    } else {
                        let file_path_raw = args.get(0).unwrap().clone();
                        let file_path = interpolate(&file_path_raw, ctx);

                        match std::fs::read_to_string(&file_path) {
                            Ok(content) => {
                                // normalize target var to include leading '$'
                                let mut target_var = var_opt.unwrap();
                                if !target_var.starts_with('$') {
                                    target_var = format!("${}", target_var);
                                }
                                ctx.variables.insert(target_var, content);
                            }
                            Err(e) => {
                                report_error(&format!("failed to read file '{}': {}", file_path, e));
                            }
                        }
                    }
                }
            }
            "ls" => {
                if args.len() < 2 {
                    report_error("ls requires <path> <target_prefix>");
                } else {
                    let dir_raw = args[0].clone();
                    let prefix_token = args[1].clone();
                    let dir_path = interpolate(&dir_raw, ctx);

                    // normalize prefix (strip leading $ if provided)
                    let prefix = prefix_token.trim_start_matches('$').to_string();

                    // If we previously recorded a total for this prefix, remove prior numbered keys
                    let prev_total_key = format!("${}total", prefix);
                    if let Some(prev_total) = ctx.variables.get(&prev_total_key) {
                        if let Ok(n) = prev_total.parse::<usize>() {
                            for i in 1..=n {
                                ctx.variables.remove(&format!("${}{}", prefix, i));
                            }
                        }
                        // also remove previous list and total entries
                        ctx.variables.remove(&prev_total_key);
                        ctx.variables.remove(&format!("${}list", prefix));
                    }

                    match std::fs::read_dir(&dir_path) {
                        Ok(entries) => {
                            let mut files: Vec<String> = Vec::new();
                            for ent in entries.filter_map(|e| e.ok()) {
                                files.push(ent.file_name().to_string_lossy().into_owned());
                            }

                            let count = files.len();

                            // store list and total with leading $
                            let total_key = format!("${}total", prefix);
                            let list_key = format!("${}list", prefix);
                            ctx.variables.insert(list_key.clone(), files.join("\n"));
                            ctx.variables.insert(total_key.clone(), count.to_string());

                            // store numbered entries: $f1, $f2, ...
                            for (i, filename) in files.iter().enumerate() {
                                let key = format!("${}{}", prefix, i + 1);
                                ctx.variables.insert(key, filename.to_string());
                            }

                            if ctx.verbose {
                                verbose_log(ctx, &format!("ls: found {} files in {}", count, dir_path));
                            }
                        }
                        Err(e) => report_error(&format!("failed to read dir '{}': {}", dir_path, e)),
                    }
                }
            }
            "find" => {
                if args.len() < 3 {
                    report_error("find usage: find $haystack_var \"needle\" $target_var");
                } else {
                    // 1. Get the haystack (handling the $ prefix)
                    let haystack_key = &args[0];
                    let haystack = if haystack_key.starts_with('$') {
                        ctx.variables.get(haystack_key).cloned().unwrap_or_default()
                    } else {
                        haystack_key.clone()
                    };

                    // 2. Get the needle (the thing we are looking for)
                    let needle = args[1].replace('"', ""); // Strip quotes if they exist

                    // 3. Perform the search
                    let target_var = &args[2];
                    let found = if haystack.contains(&needle) { "true" } else { "false" };

                    // 4. Store the result as a string
                    ctx.variables.insert(target_var.clone(), found.to_string());
                }
            }
            "args" => {
                // Check if user provided fewer args than the script expects
                if ctx.script_args.len() < args.len() {
                    let msg = format!("missing {} argument(s). expected: {}", 
                        args.len() - ctx.script_args.len(), 
                        args.join(" ")
                    );
                    verbose_log(ctx, &msg); // Pass the &str slice of the formatted message
                }

                for (i, var_name) in args.iter().enumerate() {
                    let val = ctx.script_args.get(i).cloned().unwrap_or_default();
                    ctx.variables.insert(var_name.clone(), val);
                }
            }
            "extc" => {
                // Check if we have at least a variable name and a command
                if args.len() >= 2 {
                    // Preserve leading `$` on the stored variable key for consistency
                    let mut target_var = args[0].clone();
                    if !target_var.starts_with('$') {
                        target_var = format!("${}", target_var);
                    }

                    let plugin_token = args[1].clone();
                    let plugin_name = interpolate(&plugin_token, ctx);

                    // Disallow path components in the plugin name — it must be a bare filename
                    if plugin_name.contains('/') || plugin_name.contains('\\') {
                        report_error("extc plugin name must be a bare filename located in ~/.xeon/bin");
                    } else {
                        // Construct path to ~/.xeon/bin/<plugin_name>
                        let mut exe_path = home::home_dir()
                            .map(|p| p.join(".xeon").join("bin"))
                            .unwrap_or_else(|| std::path::PathBuf::from("."));
                        exe_path.push(&plugin_name);

                        #[cfg(windows)]
                        if exe_path.extension().is_none() {
                            exe_path.set_extension("exe");
                        }

                        if exe_path.exists() {
                            // Arguments start at index 2 for extc
                            let plugin_args: Vec<String> = args[2..].iter()
                                .map(|a| interpolate(a, ctx))
                                .collect();

                            if ctx.verbose {
                                verbose_log(ctx, &format!("capturing extension: {:?} -> {}", exe_path, target_var));
                            }

                            // Execute and capture stdout
                            let output = std::process::Command::new(&exe_path)
                                .args(plugin_args)
                                .stdin(std::process::Stdio::null()) // Usually don't want stdin for capture
                                .stderr(std::process::Stdio::inherit()) // Let errors go to terminal
                                .output(); // This waits and captures stdout/stderr

                            match output {
                                Ok(out) => {
                                    // Convert bytes to string (lossy handles weird characters safely)
                                    let result = String::from_utf8_lossy(&out.stdout).trim().to_string();

                                    // Store the result in your context using the $-prefixed key
                                    ctx.variables.insert(target_var, result);

                                    if !out.status.success() && ctx.verbose {
                                        verbose_log(ctx, &format!("extension {} failed with code: {}", plugin_name, out.status));
                                    }
                                }
                                Err(e) => report_error(&format!("failed to start {}: {}", plugin_name, e)),
                            }
                        } else {
                            report_error(&format!("binary not found in ~/.xeon/bin: {}", plugin_name));
                        }
                    }
                } else {
                    report_error("extc requires a variable name and a plugin name: extc $var cmd args...");
                }
            }
            "get" => {
                if !args.is_empty() {
                    let as_idx = args.iter().position(|s| s == "as");

                    // 1. Identify Expression Parts and Target Variable
                    let (expr_parts, var_name_opt) = if let Some(i) = as_idx {
                        (args[..i].to_vec(), args.get(i + 1).cloned())
                    } else {
                        report_error("get requires 'as $var' syntax");
                        return None;
                    };

                    // 2. Evaluate Parts (just like your string command)
                    let mut evaluated_parts: Vec<String> = Vec::new();
                    let mut i = 0;
                    while i < expr_parts.len() {
                        if expr_parts[i] == "+" {
                            i += 1;
                            continue;
                        }
                        evaluated_parts.push(interpolate(&expr_parts[i], ctx));
                        i += 1;
                    }

                    // 3. The built key (e.g., "f1")
                    let lookup_key_raw = evaluated_parts.join("");
                    
                    // Ensure the lookup key has a '$' prefix if your interpolate/storage expects it
                    // Based on your string code, keys in ctx.variables seem to include the '$'
                    let lookup_key = if lookup_key_raw.starts_with('$') { 
                        lookup_key_raw 
                    } else { 
                        format!("${}", lookup_key_raw) 
                    };

                    if let Some(var_name) = var_name_opt {
                        // 4. Perform the "Get" lookup
                        let value = ctx.variables.get(&lookup_key).cloned().unwrap_or_default();
                        
                        // 5. Store in the target variable
                        // (Using your string command's standard variable insertion logic)
                        ctx.variables.insert(var_name, value);
                    }
                }
            }
            "sleep" => {
                if let Some(duration_str) = args.get(0) {
                    let ms_str = interpolate(duration_str, ctx);
                    if let Ok(ms) = ms_str.parse::<u64>() {
                        std::thread::sleep(std::time::Duration::from_millis(ms));
                    } else {
                        report_error(&format!("sleep: invalid duration '{}'", ms_str));
                    }
                } else {
                    report_error("sleep requires a duration in milliseconds");
                }
            }
            "exit" => std::process::exit(0),
            _ => {}
        },
        ASTNodeKind::Repeat { times, var, body } => {
            let n = if times.starts_with('$') {
                ctx.variables.get(times).and_then(|v| v.parse::<usize>().ok()).unwrap_or(1)
            } else {
                times.parse::<usize>().unwrap_or(1)
            };

            for i in 1..=n {
                if let Some(var_name) = var {
                    ctx.variables.insert(var_name.clone(), i.to_string());
                }

                let mut pc = 0;
                while pc < body.len() {
                    if let Some(jump) = execute_node(&body[pc], ctx) {
                        // handle go inside repeat
                        // jump line numbers relative to AST's line map
                        if let Some(&target_ptr) = ctx.line_map.get(&jump) {
                            pc = body.iter().position(|n| n as *const _ == target_ptr).unwrap_or(pc + 1);
                            continue;
                        }
                    }
                    pc += 1;
                }
            }

            // optional: remove loop variable after done
            if let Some(var_name) = var {
                ctx.variables.remove(var_name);
            }
        }
            ASTNodeKind::If { condition, body, else_body } => {
            // prepare condition safely (quote strings, substitute vars)
            let interp = prepare_condition(condition, ctx);
            match evalexpr::eval_boolean(&interp) {
                Ok(true) => execute_ast(&body, ctx),
                Ok(false) => execute_ast(&else_body, ctx),
                Err(e) => {
                    report_error(&format!("if eval error: {} (expr='{}')", e, interp));
                    // fallback: treat non-empty interpolated string as truthy
                    if !interp.is_empty() {
                        execute_ast(&body, ctx);
                    } else {
                        execute_ast(&else_body, ctx);
                    }
                }
            }
        }
        &ASTNodeKind::Func { .. } => {
            // function definitions are handled before execution; no-op at runtime
        }
    }
    None
}

fn read_xeo(path: &PathBuf, reverse: bool, verbose: bool, script_args: Vec<String>) {
    match fs::read_to_string(path) {
        Ok(content) => {
            println!("{} {}", "[xeo] read".green(), format!("{:?}", path));
            handle_xeo(content, reverse, path, verbose, script_args);
        },
        Err(e) => {
            report_error(&format!("failed to read xeo script: {}", e));
        }
    }
}

fn handle_xeo(script: String, reverse: bool, script_path: &PathBuf, verbose: bool, script_args: Vec<String>) {
    println!("{} .xeo {}", "[xeo] interpreting".green(), "script...".green());
    let pwd = PathBuf::from(get_current_path());
    let dir = home::home_dir()
        .map(|p| p.join(".xeon")) // Only joins if home_dir() returned Some
        .unwrap_or_else(|| {
            report_error("could not determine home directory; defaulting to current dir");
            PathBuf::from(".")
        });

    let tokenized = lex_lines(&script);
    let ast = parse_tokens(tokenized);
    let mut ctx = Context::new();
    ctx.reverse_mode = reverse;
    ctx.verbose = verbose;
    // resolve script path to an absolute path and record script directory for backups/revlogs
    let script_abs = std::fs::canonicalize(script_path).unwrap_or_else(|_| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(script_path)
    });
    ctx.script_dir = script_abs.parent().map(|p| p.to_path_buf());
    ctx.script_args = script_args;
    // revlog will live in ~/.xeon as <script-stem>.revlog
    let revlog_path = {
        let d = get_xeon_dir();
        let stem = script_abs.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "script".to_string());
        d.join(format!("{}.revlog", stem))
    };
    if ctx.verbose {
        verbose_log(&ctx, &format!("script_path abs: {}", script_abs.display()));
        verbose_log(&ctx, &format!("script_dir={}", ctx.script_dir.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| String::from("."))));
        verbose_log(&ctx, &format!("revlog will be: {}", revlog_path.display()));
    }

    if reverse {
        // run reverse ops from revlog
        if revlog_path.exists() {
            let ops = deserialize_revlog(&revlog_path);
            if ops.is_empty() {
                report_error(&format!("no reverse ops found in {}", revlog_path.display()));
            } else {
                execute_reverse_ops(ops, ctx.script_dir.clone(), ctx.verbose);
                println!("{} reversed operations from {}", "[xeo]".green(), revlog_path.display());
            }
        } else {
            report_error(&format!("no revlog found at {}", revlog_path.display()));
        }
        return;
    }

    // Normal execution: run AST and persist reverse ops
    execute_ast(&ast, &mut ctx);

    change_path(&dir).unwrap_or_else(|e| {
        report_error(&format!("could not find .xeon directory: {}", e));
        pwd.clone()
    });
    if !ctx.reverse_ops.is_empty() {
        // write revlog into ~/.xeon with script-stem.revlog
        let rev_dir = get_xeon_dir();
        if let Err(e) = std::fs::create_dir_all(&rev_dir) {
            report_error(&format!("could not create revlog dir {}: {}", rev_dir.display(), e));
        } else {
            let stem = script_abs.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "script".to_string());
            let out_path = rev_dir.join(format!("{}.revlog", stem));
            serialize_revlog(&out_path, &ctx.reverse_ops);
            println!("{} wrote revlog to {}", "[xeo]".green(), out_path.display());
        }
    }
    change_path(&pwd).unwrap_or_else(|e| {
        report_error(&format!("could not restore original directory: {}", e));
        pwd.clone()
    });
}

fn main() {
    let cli = Cli::parse();
    let path = cli.path.unwrap_or_else(|| "main.xeo".to_string());
    if cli.version {
         println!("{}", ABOUT);
         println!("{}", VERSION);
         return;
    }

    if cli.reverse {
        println!("{} {}", "[xeo] reversing file operations on".green(), path);
    } else {
        println!("{} \"{}\"", "[xeo] handling file".green(), path);
    }
    read_xeo(&PathBuf::from(path), cli.reverse, cli.verbose, cli.script_args);
}