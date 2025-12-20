use clap::Parser;
use colored::*;
use std::path::PathBuf;
use std::fs;
use std::io::Write;
use std::io;
use std::process::Command;
use std::process;
use std::env;
use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Parser, Debug)]
#[command(name = "xeo", about = ABOUT, version = VERSION, disable_version_flag = true)]
struct Cli {
  /// reverses .xeo operations
  #[arg(short, long)]
  reverse: bool,
  
  /// prints current .xeo version
  #[arg(short, long)]
  version: bool,
  
  path: String,
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
#[derive(Debug)]
enum ASTNodeKind {
    Command { name: String, args: Vec<String> },
    Repeat { times: String, var: Option<String>, body: Vec<ASTNode> },
    Func { name: String, body: Vec<ASTNode> },
    If { condition: String, body: Vec<ASTNode>, else_body: Vec<ASTNode> },
}

#[derive(Debug)]
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
            Some(Token::Command(cmd)) if cmd == "func" => {
                let name = tokens.get(1).map(|t| match t {
                    Token::StringLiteral(s) => s.clone(),
                    Token::Command(s) => s.clone(),
                    _ => "unnamed".to_string(),
                }).unwrap_or_else(|| "unnamed".to_string());

                let (body, consumed) = parse_block(lines, i+1, end_idx);
                ast.push(ASTNode {
                    kind: ASTNodeKind::Func { name, body },
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
}

impl Context {
    fn new() -> Self {
        Self { variables: HashMap::new(), line_map: HashMap::new() }
    }
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

fn execute_ast(ast: &[ASTNode], ctx: &mut Context) {
    // build line map for go
    for node in ast {
        ctx.line_map.insert(node.line_number, node as *const ASTNode);
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
                    } else if args.len() >= 2 && args.last().unwrap().starts_with('$') {
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
                        ctx.variables.insert(var_name, value);
                    }
                }
            }
            "ask" => {
                if let Some(var) = args.get(0) {
                    print!("> ");
                    io::stdout().flush().unwrap();
                    let mut input = String::new();
                    io::stdin().read_line(&mut input).unwrap();
                    ctx.variables.insert(var.clone(), input.trim().to_string());
                }
            }
            "go" => {
                if let Some(target_line) = args.get(0) {
                    if let Ok(line) = target_line.parse::<usize>() {
                        return Some(line);
                    }
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
            // simple string truthiness
            let cond_val = if condition.starts_with('$') {
                ctx.variables.get(condition).cloned().unwrap_or_default()
            } else {
                condition.clone()
            };
            if !cond_val.is_empty() {
                execute_ast(&body, ctx);
            } else {
                execute_ast(&else_body, ctx);
            }
        }
        &ASTNodeKind::Func { .. } => todo!()
    }
    None
}

fn read_xeo(path: &PathBuf, reverse: bool) {
    match fs::read_to_string(path) {
        Ok(content) => {
            println!("{}", "read xeo script");
            handle_xeo(content, reverse);
        },
        Err(e) => {
            eprintln!("{} {}", "failed to read xeo script:".red(), e);
        }
    }
}

fn handle_xeo(script: String, reverse: bool) {
    println!("{}", "handling xeo script...");
    let pwd = PathBuf::from(get_current_path());
    let mut dir = home::home_dir().unwrap().join(" ");

    let tokenized = lex_lines(&script);
    let ast = parse_tokens(tokenized);
    let mut ctx = Context::new();
    execute_ast(&ast, &mut ctx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lex_handles_plus_and_quotes() {
        let tokens = lex_line(r#""a"+"b" as $n"#);
        assert_eq!(tokens.len(), 5);
        match &tokens[0] { Token::StringLiteral(s) => assert_eq!(s, "a"), _ => panic!("expected string") }
        match &tokens[1] { Token::Command(c) => assert_eq!(c, "+"), _ => panic!("expected +") }
        match &tokens[2] { Token::StringLiteral(s) => assert_eq!(s, "b"), _ => panic!("expected string") }
        match &tokens[3] { Token::Command(c) => assert_eq!(c, "as"), _ => panic!("expected as") }
        match &tokens[4] { Token::Variable(v) => assert_eq!(v, "$n"), _ => panic!("expected var") }
    }

    #[test]
    fn string_command_concatenates_and_assigns() {
        let script = r#"string "a" + "b" as $n"#;
        let tokenized = lex_lines(script);
        let ast = parse_tokens(tokenized);
        let mut ctx = Context::new();
        execute_ast(&ast, &mut ctx);
        assert_eq!(ctx.variables.get("$n").map(|s| s.as_str()), Some("ab"));
    }

    #[test]
    fn string_command_interpolates_vars() {
        let script = r#"string "$x" + "z" as $n"#;
        let tokenized = lex_lines(script);
        let ast = parse_tokens(tokenized);
        let mut ctx = Context::new();
        ctx.variables.insert("$x".into(), "y".into());
        execute_ast(&ast, &mut ctx);
        assert_eq!(ctx.variables.get("$n").map(|s| s.as_str()), Some("yz"));
    }
}

fn main() {
    let cli = Cli::parse();
    if cli.reverse {
         println!("{} {}", "[xeo] reversing file operations on".green(), cli.path);
         println!("in construction!");
    } else {
         println!("{} {}", "[xeo] handling file".green(), cli.path);
         read_xeo(&PathBuf::from(cli.path), cli.reverse);
     }
     if cli.version {
         println!("{}", ABOUT);
         println!("{}", VERSION);
    }
}