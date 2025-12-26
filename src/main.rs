use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::collections::HashMap;
use std::io::{self, Write};
use evalexpr::{HashMapContext, Value, eval_with_context, ContextWithMutableVariables};
use std::sync::atomic::{AtomicBool, Ordering};

fn get_xeon_dir() -> PathBuf {
    #[cfg(windows)]
    let mut path = PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default());
    
    #[cfg(unix)]
    let mut path = PathBuf::from(std::env::var("HOME").unwrap_or_default());

    path.push(".xeon");
    path
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    
    // 1. Detect and remove flags
    let verbose = args.iter().any(|arg| arg == "-v" || arg == "--verbose");
    let ultra_verbose = args.iter().any(|arg| arg == "-vv" || arg == "--trace" || arg == "--debug");
    let reverse = args.iter().any(|arg| arg == "-r" || arg == "--reverse");
    let version = args.iter().any(|arg| arg == "-V" || arg == "--version");

    let verbose = verbose || ultra_verbose;
    
    // Remove flags from the vector so they don't interfere with path/script args
    args.retain(|arg| !arg.starts_with('-'));

    // 2. Decide mode based on remaining args
    if version {
        println!("{BLUE}the .xeo scripting lang{ESC}");
        println!("v4.0.0 build number 400-3");
        return;
    }
    if args.len() < 2 {
        // Pass flags into your mode handler
        mode("interactive", &args, verbose, reverse, ultra_verbose);
        return;
    }
    
    mode("script", &args, verbose, reverse, ultra_verbose);
}

//================================//
//---------- variables -----------//
//================================//
#[derive(Debug)]
pub struct Instruction {
    pub name: String,
    pub args: Vec<String>,
    pub line_num: usize,
    pub jump_to: Option<usize>,
}

pub struct Context {
    pub variables: std::collections::HashMap<String, String>,
    pub functions: HashMap<String, usize>,
    pub signal: Signal,
    pub corefuncs: Vec<String>,

    pub return_stack: Vec<usize>,
    pub loop_stack: Vec<usize>,
    pub arg_stack: Vec<Vec<String>>,
    pub program: Vec<Instruction>,
    pub pc: usize,
    
    pub script_path: String,
    pub loaded_modules: HashSet<String>,
    pub ultra_verbose: bool,
    pub verbose: bool,
    pub reverse: bool,
}

impl Context {
    fn report_error(&self, msg: &str, line_num: usize) {
        let path = self.variables.get("script_path").unwrap_or(&self.script_path);
        eprintln!("{RED}[xeo] err: {ESC}{msg} {DIM}({path}:{line_num}){ESC}");
    }
}

struct Token {
    val: String,
    line: usize,
}

#[derive(PartialEq)]
pub enum Signal {
    None,
    Break,
    Continue,
    Return,
}

const RED: &str = "\x1b[31m";
const BLUE: &str = "\x1b[34m";
const DIM: &str = "\x1b[2m";
const ESC: &str = "\x1b[0m";

static SHOULD_STOP: AtomicBool = AtomicBool::new(false);

//================================//
//------- helper functions -------//
//================================//
fn resolve_vars(text: &str, ctx: &Context) -> String {
    let mut result = text.to_string();
    
    // Sort keys by length descending so $element is replaced before $e
    let mut keys: Vec<_> = ctx.variables.keys().collect();
    keys.sort_by_key(|k| std::cmp::Reverse(k.len()));

    for name in keys {
        let value = &ctx.variables[name];
        
        let clean_name = name.trim_start_matches('$');
        let placeholder = format!("${}", clean_name);
        
        if result.contains(&placeholder) {
            result = result.replace(&placeholder, value);
        }
    }
    result
}

fn evaluate(args: &[String], ctx: &Context) -> Value {
    let mut expr_parts = Vec::new();
    let operators = ["==", "!=", ">", "<", ">=", "<=", "&&", "||", "+", "-", "*", "/"];

    for arg in args {
        if arg.starts_with('$') {
            // Variable: strip $ for evalexpr lookup
            expr_parts.push(arg.trim_start_matches('$').to_string());
        } else if operators.contains(&arg.as_str()) || arg.parse::<f64>().is_ok() {
            // Operator or Number: leave as-is
            expr_parts.push(arg.clone());
        } else {
            // String Literal: wrap in quotes if not already quoted
            if arg.starts_with('"') && arg.ends_with('"') {
                expr_parts.push(arg.clone());
            } else {
                expr_parts.push(format!("\"{}\"", arg));
            }
        }
    }
    
    let expr = expr_parts.join(" ");
    
    let mut eval_ctx = HashMapContext::new();
    for (name, val) in &ctx.variables {
        let clean_name = name.trim_start_matches('$');
        if let Ok(n) = val.parse::<f64>() {
            let _ = eval_ctx.set_value(clean_name.into(), Value::Float(n));
        } else {
            let _ = eval_ctx.set_value(clean_name.into(), Value::String(val.clone()));
        }
    }

    eval_with_context(&expr, &eval_ctx).unwrap_or(Value::from(false))
}

fn verbose_log(ctx: &Context, msg: &str) {
    if ctx.verbose {
        println!("{BLUE}[xeo] dbg: {ESC}{msg}");
    }
}

fn clean_multiline(input: &str) -> String {
    input.lines()
        .map(|line| line.trim_start_matches('\t').trim_start_matches(' '))
        .collect::<Vec<_>>()
        .join("\n")
        .trim() // Removes the very first and last newlines from the " " quotes
        .to_string()
}

fn is_block_complete(input: &str) -> bool {
    let mut depth = 0;
    let mut in_quotes = false;
    
    // Simple character scan for quotes and block keywords
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '"' && (i == 0 || chars[i-1] != '\\') {
            in_quotes = !in_quotes;
        }
        
        if !in_quotes {
            // Check for block starts (must be surrounded by boundaries or start of string)
            let remaining = &input[i..];
            if remaining.starts_with("func") || remaining.starts_with("if") || remaining.starts_with("repeat") || remaining.starts_with("def") || remaining.starts_with("function") {
                depth += 1;
            } else if remaining.starts_with("end") {
                depth -= 1;
            }
        }
        i += 1;
    }
    depth <= 0
}

//================================//
//------ handler functions -------//
//================================//
fn read_xeo(path: &PathBuf, ctx: &mut Context) -> Vec<Instruction> {
    match fs::read_to_string(path) {
        Ok(content) => {
            parse(&content, ctx)
        },
        Err(e) => {
            ctx.report_error(&format!("failed to read xeo script: {}", e), 0);
            Vec::new()
        }
    }
}

fn mode(mode: &str, args: &Vec<String>, verbose: bool, reverse: bool, ultra_verbose: bool) {
    // Create one context that lives as long as the mode
    let path_str = args.get(1).cloned().unwrap_or_else(|| String::from("interactive"));
    let mut ctx = Context {
        variables: HashMap::new(),
        functions: HashMap::new(),
        signal: Signal::None,
        corefuncs: Vec::new(),

        return_stack: Vec::new(),
        loop_stack: Vec::new(),
        arg_stack: Vec::new(),
        program: Vec::new(),
        script_path: path_str.clone(),

        pc: 0,
        loaded_modules: HashSet::new(),
        ultra_verbose,
        verbose,
        reverse,
    };
    let script_path = PathBuf::from(&path_str);

    match mode {
        "interactive" => {
            ctrlc::set_handler(move || {
                SHOULD_STOP.store(true, Ordering::SeqCst);
                println!("\n{DIM}interrupted (use 'exit' to exit interpreter){ESC}");
            }).ok();

            println!("{DIM}arrow keys for history, enter for execute/new line.{ESC}");
            println!("{BLUE}xeo v4.0.0 (interactive){ESC}");

            use rustyline::error::ReadlineError;
            use rustyline::{Cmd, DefaultEditor, Modifiers, KeyCode, KeyEvent};

            let mut rl = DefaultEditor::new().unwrap();
            let mut accumulator = String::new();

            rl.bind_sequence(
                KeyEvent(KeyCode::Tab, Modifiers::NONE), 
                Cmd::Insert(1, "  ".to_string()) // Inserts exactly 4 spaces
            );

            loop {
                // Change prompt if we are inside a block
                let prompt = if accumulator.is_empty() { "\x1b[34m>>\x1b[0m " } else { "\x1b[34m..\x1b[0m " };
                
                let readline = rl.readline(prompt);
                match readline {
                    Ok(line) => {
                        if line.trim() == "exit" { break; }
                        
                        // Add to history so Up/Down arrows work
                        let _ = rl.add_history_entry(line.as_str());
                        
                        accumulator.push_str(&line);
                        accumulator.push('\n');

                        if is_block_complete(&accumulator) {
                            let new_instrs = parse(&accumulator, &mut ctx);
                            
                            // Add to permanent memory
                            ctx.program.extend(new_instrs);
                            
                            // Execute
                            execute(&mut ctx);
                            
                            accumulator.clear();
                        }
                    }
                    Err(ReadlineError::Interrupted) => { // Ctrl-C
                        println!("{DIM}interrupted (use 'exit' to exit interpreter){ESC}");
                        accumulator.clear();
                    }
                    Err(ReadlineError::Eof) => { // Ctrl-D
                        break;
                    }
                    Err(err) => {
                        println!("{RED}[xeo] err:{ESC} {:?}", err);
                        break;
                    }
                }
            }
        }
        "script" => {
            // 1. Load and Parse the whole file
            let program = read_xeo(&script_path, &mut ctx);
            ctx.program = program;
            
            // 2. Run the whole program
            ctx.pc = 0;
            execute(&mut ctx);
        },
        _ => println!("Unknown mode: {}", mode),
    }
}

//================================//
//-------- lexer & parser --------//
//================================//
fn lex(content: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut line_count = 1;
    let mut token_start_line = 1; // Track where a multi-line token began
    let mut chars = content.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next_c) = chars.next() {
                    match next_c {
                        'n' => current.push('\n'),
                        't' => current.push('\t'),
                        _ => current.push(next_c),
                    }
                }
            }
            '#' if !in_quotes => {
                while let Some(&next) = chars.peek() {
                    if next == '\n' { break; }
                    chars.next();
                }
            }
            '"' => {
                if !in_quotes {
                    // This is the start of a string: record the line number
                    token_start_line = line_count;
                }
                in_quotes = !in_quotes;
                // Quote removed from token (as requested)
            }
            '\n' => {
                if in_quotes {
                    // Inside quotes: the newline is part of the string data
                    current.push('\n');
                } else {
                    // Outside quotes: the newline acts as a delimiter
                    if !current.is_empty() {
                        tokens.push(Token { val: current.clone(), line: token_start_line });
                        current.clear();
                    }
                }
                line_count += 1;
                // If we aren't mid-token, the next token starts here
                if current.is_empty() {
                    token_start_line = line_count;
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(Token { val: current.clone(), line: token_start_line });
                    current.clear();
                }
                // Update start line for the next token to the current line
                token_start_line = line_count;
            }
            _ => {
                if current.is_empty() && !in_quotes {
                    token_start_line = line_count;
                }
                current.push(c);
            }
        }
    }
    
    if !current.is_empty() {
        tokens.push(Token { val: current, line: token_start_line });
    }
    tokens
}

fn parse_tokens(tokens: Vec<Token>, ctx: &Context) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut i = 0;
    
    // Hardcoded language keywords
    let base_commands = [
        "print", "set", "if", "else", "end", "repeat", "func", 
        "run", "ask", "coreadd", "wait", "exit", "fetch", 
        "wget", "return", "break", "continue", "use", "ext", "extc", "input",
        "sleep", "import", "call", "def", "function", "let"
    ];

    while i < tokens.len() {
        let name = tokens[i].val.clone();
        let line_num = tokens[i].line;

        // Check if the token is a known command OR a coreadd function
        let is_command = base_commands.contains(&name.as_str()) || ctx.corefuncs.contains(&name);

        if is_command {
            i += 1;
            let mut args = Vec::new();
            // Greedy: take everything else on this line as an argument
            while i < tokens.len() && tokens[i].line == line_num {
                args.push(tokens[i].val.clone());
                i += 1;
            }

            instructions.push(Instruction {
                name,
                args,
                jump_to: None,
                line_num,
            });
        } else {
            i += 1;
        }
    }
    instructions
}

fn parse(content: &str, ctx: &mut Context) -> Vec<Instruction> {
    let mut program = Vec::new();
    let mut stack = Vec::new(); // This tracks the "unclosed" repeats
    let tokens = lex(content);

    // PRE-PASS SCANNER: Find coreadd functions
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i].val == "coreadd" {
            if let Some(name_token) = tokens.get(i + 1) {
                ctx.corefuncs.push(name_token.val.clone());
            }
        }
        i += 1;
    }

    // PASS 1: Create the instructions
    parse_tokens(tokens, ctx)
        .into_iter()
        .enumerate()
        .for_each(|(_idx, instr)| {
            program.push(instr);
        });

    // PASS 2: The Linker (Matches repeat with end)
    for i in 0..program.len() {
        match program[i].name.as_str() {
            "if" | "repeat" => stack.push(i),
            "func" => {
                let func_name = program[i].args[0].clone();
                ctx.functions.insert(func_name, i);
                stack.push(i);
            }
            "else" => {
                if let Some(if_idx) = stack.pop() {
                    program[if_idx].jump_to = Some(i); // if -> else
                    stack.push(i); // else -> end
                }
            }
            "end" => {
                if let Some(start_idx) = stack.pop() {
                    let parent = program[start_idx].name.clone();
                    program[start_idx].jump_to = Some(i); // Link start to this end

                    if parent == "repeat" {
                        program[i].jump_to = Some(start_idx); // Loop back
                    } else {
                        program[i].jump_to = None; // if/else/func ends don't jump back
                    }
                }
            }
            _ => {}
        }
    }
    
    // Check if any repeats were left unclosed
    for open_loop in stack {
        ctx.report_error("'repeat' on line {} never ended", program[open_loop].line_num);
    }

    program
}

//================================//
//--------- interpreter ----------//
//================================//
fn execute(ctx: &mut Context) {
    while ctx.pc < ctx.program.len() {
        let instr = &ctx.program[ctx.pc];

        if SHOULD_STOP.load(Ordering::SeqCst) {
            SHOULD_STOP.store(false, Ordering::SeqCst); // Reset for next time
            break; // Exit the loop and return to REPL
        }

        // --- SIGNAL HANDLING ---
        if ctx.signal == Signal::Return {
             // If we found the function end (and it's not a loop end), stop skipping
            if instr.name == "end" && instr.jump_to.is_none() {
                // Fall through to execute 'end', which pops the stack
            } else {
                ctx.pc += 1;
                continue; 
            }
        }

        if ctx.ultra_verbose {
            verbose_log(ctx, format!("{} {DIM}({}:{}){ESC}", instr.name, ctx.script_path, instr.line_num).as_str());
        }

        match instr.name.as_str() {
            //================//
            //----general----//
            //================//
            "print" => {
                let output = resolve_vars(clean_multiline(&instr.args.join(" ")).as_str(), ctx);
                println!("{}", output);
            }
            "ask" | "input" => {
                let prompt = instr.args.get(1).map(|s| s.as_str()).unwrap_or("> ");
                print!("{}", prompt);
                
                // CRITICAL: Flush stdout so the prompt appears BEFORE read_line
                io::stdout().flush().unwrap();

                let mut input = String::new();
                match io::stdin().read_line(&mut input) {
                    Ok(_n) => {
                        let var_name = instr.args.get(0)
                            .expect("$var missing")
                            .trim_start_matches('$')
                            .to_string();
                        
                        // Trim the newline from the user's input before saving
                        ctx.variables.insert(var_name, input.trim().to_string());
                        verbose_log(ctx, format!("user input: {}", input.trim().to_string()).as_str());
                    }
                    Err(e) => {
                        ctx.report_error(&format!("{}", e), instr.line_num);
                    }
                }
            }
            "fetch" => {
                let url = resolve_vars(&instr.args[0], ctx);
                verbose_log(ctx, &format!("fetching {}...", url));

                // 1. Use send_lazy to stream the response
                match minreq::get(&url).with_max_redirects(5).send_lazy() {
                    Ok(res) => {
                        let mut body_accumulator = Vec::new(); // Use a Vec to collect bytes
                        let mut chunk_buffer = Vec::with_capacity(8192); // 8KB check-point

                        for byte_result in res {
                            // 2. CHECK INTERRUPT (Every byte or every chunk)
                            if SHOULD_STOP.load(Ordering::SeqCst) {
                                println!("{BLUE}[xeo] fetch:{ESC} aborted by user");
                                return; 
                            }

                            if let Ok((byte, _)) = byte_result {
                                chunk_buffer.push(byte);
                                
                                // 3. Move from chunk buffer to main body
                                if chunk_buffer.len() >= 8192 {
                                    body_accumulator.append(&mut chunk_buffer);
                                }
                            }
                        }
                        
                        // 4. Finalize the remaining bytes
                        body_accumulator.append(&mut chunk_buffer);

                        // 5. Convert to String and store in 'res' variable
                        let final_body = String::from_utf8_lossy(&body_accumulator).to_string();
                        ctx.variables.insert("res".to_string(), final_body);
                    }
                    Err(e) => ctx.report_error(&format!("fetch failed: {}", e), instr.line_num),
                }
            }
            "find" => {
                let haystack = resolve_vars(&instr.args[0], ctx);
                let needle = resolve_vars(&instr.args[1], ctx);
                let dest_var = &instr.args[2]; // The $bool variable name

                let found = haystack.contains(&needle);
                ctx.variables.insert(dest_var.clone(), found.to_string());
            }
            "get" => {
                // args[0] is the "string expression" (e.g., "pkg$i")
                // args[1] is the "as" keyword (we can skip it)
                // args[2] is the destination variable name
                
                let dynamic_name = resolve_vars(&instr.args[0], ctx);
                let value = ctx.variables.get(&dynamic_name).cloned().unwrap_or_default();
                
                let dest_var = &instr.args[2];
                ctx.variables.insert(dest_var.clone(), value);
            }
            //================//
            //---core stuff---//
            //================//
            "ext" | "extc" => {
                let is_capture = instr.name == "extc";
                let cmd_name = resolve_vars(&instr.args[0], ctx);
                
                // FORCE the path to ~/.xeon/bin
                let cmd_path = get_xeon_dir().join("bin").join(&cmd_name);
                
                // Check if it exists before trying to run it
                if !cmd_path.exists() {
                    ctx.report_error(&format!("command not found in xeon/bin: {}", cmd_name), instr.line_num);
                    return;
                }

                let args: Vec<String> = instr.args[1..].iter()
                    .map(|arg| resolve_vars(arg, ctx))
                    .collect();

                let mut command = std::process::Command::new(cmd_path);
                command.args(args);

                if is_capture {
                    match command.output() {
                        Ok(out) => {
                            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                            ctx.variables.insert("res".to_string(), stdout);
                        }
                        Err(e) => ctx.report_error(&format!("extc failed: {}", e), instr.line_num),
                    }
                } else {
                    match command.spawn() {
                        Ok(mut child) => { child.wait().ok(); }
                        Err(e) => ctx.report_error(&format!("ext failed: {}", e), instr.line_num),
                    }
                }
            }
            "use" | "import" => {
                let raw_name = resolve_vars(&instr.args[0], ctx);
                let mut final_path = None;

                // 1. Define the search locations in order of priority
                let local_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
                let xeon_lib_dir = get_xeon_dir().join("lib"); // Points to ~/.xeon/lib

                let search_dirs = vec![local_dir, xeon_lib_dir];

                'search: for dir in search_dirs {
                    // Step A: Try the exact name
                    let exact_path = dir.join(&raw_name);
                    if exact_path.is_file() {
                        final_path = Some(exact_path);
                        break 'search;
                    }

                    // Step B: Try with .xeo extension
                    if !raw_name.ends_with(".xeo") {
                        let path_with_ext = dir.join(format!("{}.xeo", raw_name));
                        if path_with_ext.is_file() {
                            final_path = Some(path_with_ext);
                            break 'search;
                        }
                    }
                }

                match final_path {
                    Some(path) => {
                        match std::fs::read_to_string(&path) {
                            Ok(content) => {
                                verbose_log(ctx, &format!("using: {:?}", path));
                                
                                // Standard sub-parser swap to protect global PC/program
                                let sub_program = parse(&content, ctx);
                                let old_pc = ctx.pc;
                                let old_program = std::mem::replace(&mut ctx.program, sub_program);
                                
                                ctx.pc = 0;
                                execute(ctx);
                                
                                ctx.program = old_program;
                                ctx.pc = old_pc;
                            }
                            Err(e) => ctx.report_error(&format!("failed to read module {:?}: {}", path, e), instr.line_num),
                        }
                    }
                    None => ctx.report_error(&format!("module '{}' not found in local dir or ~/.xeon/lib", raw_name), instr.line_num),
                }
            }
            "wait" | "sleep" => {
                let ms_str = instr.args.get(0).map(|s| s.as_str()).unwrap_or("0");
                if let Ok(mut remaining_ms) = ms_str.parse::<u64>() {
                    // Break the wait into 100ms chunks
                    while remaining_ms > 0 {
                        // 1. Check if we should stop immediately
                        if SHOULD_STOP.load(Ordering::SeqCst) {
                            break; 
                        }

                        // 2. Decide how long to sleep this chunk (max 100ms)
                        let sleep_chunk = if remaining_ms > 100 { 100 } else { remaining_ms };
                        std::thread::sleep(std::time::Duration::from_millis(sleep_chunk));
                        
                        remaining_ms -= sleep_chunk;
                    }
                }
            }
            "set" | "let" => {
                let arg0 = &instr.args[0];
                
                let var_name = if arg0.starts_with("$$") {
                    let pointer_name = &arg0[2..];
                    ctx.variables.get(pointer_name)
                        .or_else(|| ctx.variables.get(&format!("${}", pointer_name)))
                        .cloned()
                        .unwrap_or_else(|| pointer_name.to_string())
                } else {
                    arg0.trim_start_matches('$').to_string()
                };

                // Safety check: Ensure we don't insert an empty string as a key
                let final_key = var_name.trim_start_matches('$').to_string();
                if final_key.is_empty() {
                    return; // Or report an error
                }

                let expression_parts = &instr.args[1..];
                let resolved_parts: Vec<String> = expression_parts.iter()
                    .map(|p| resolve_vars(p, ctx))
                    .collect();

                let full_expr = resolved_parts.join(" ");
                let is_math = !full_expr.contains('"') && 
                            full_expr.chars().any(|c| "+-*/%() ".contains(c));

                if is_math {
                    match evalexpr::eval(&full_expr) {
                        Ok(value) => {
                            ctx.variables.insert(final_key, value.to_string());
                        }
                        Err(_) => {
                            ctx.variables.insert(final_key, full_expr);
                        }
                    }
                } else {
                    let mut final_str = String::new();
                    for part in resolved_parts {
                        if part != "+" {
                            final_str.push_str(&part.replace('"', ""));
                        }
                    }
                    ctx.variables.insert(final_key, final_str);
                }
            }
            "break" => {
                ctx.signal = Signal::Break;
                // Jump to the current loop's start so 'repeat' can handle the break
                if let Some(&loop_start) = ctx.loop_stack.last() {
                    ctx.pc = loop_start; 
                    continue; // Skip increment, let 'repeat' handle it
                }
            }
            "continue" => {
                ctx.signal = Signal::Continue;
                // Jump to the current loop's start
                if let Some(&loop_start) = ctx.loop_stack.last() {
                    ctx.pc = loop_start;
                    continue;
                }
            }
            "return" => {
                ctx.signal = Signal::Return;
            }
            "func" | "def" | "function" => {
                // If the arg_stack is empty, it means we didn't 'call' this.
                // We are just naturally reading the file. SKIP IT.
                if ctx.arg_stack.is_empty() {
                    if let Some(end_pos) = instr.jump_to {
                        ctx.pc = end_pos + 1; // Jump PAST the end of the function
                        continue; 
                    }
                }

                // Mapping logic for actual calls
                if let Some(passed_values) = ctx.arg_stack.pop() {
                    for (i, val_name) in instr.args.iter().skip(1).enumerate() {
                        if let Some(val) = passed_values.get(i) {
                            let key = val_name.trim_start_matches('$').to_string();
                            ctx.variables.insert(key, val.clone());
                        }
                    }
                }
            }
            "run" | "call" => {
                let name = &instr.args[0];
                if let Some(&target_pc) = ctx.functions.get(name) {
                    let mut vals = Vec::new();
                    for arg in instr.args.iter().skip(1) {
                        vals.push(resolve_vars(arg, ctx));
                    }
                    ctx.arg_stack.push(vals);
                    
                    // Save the address to return to (the instruction AFTER call)
                    ctx.return_stack.push(ctx.pc + 1); 
                    
                    ctx.pc = target_pc;
                    continue; // Jump immediately to the 'func' line
                }
            }
            "repeat" => {
                // 1. Register this loop in the stack
                if !ctx.loop_stack.contains(&ctx.pc) {
                     ctx.loop_stack.push(ctx.pc);
                }

                // 2. Handle Signals (The "Rewind" Strategy)
                if ctx.signal == Signal::Break {
                    ctx.signal = Signal::None;
                    ctx.loop_stack.pop(); // We are leaving this loop
                    
                    if let Some(end_pos) = instr.jump_to {
                        ctx.pc = end_pos; // Jump out!
                        // Cleanup logic...
                        continue; // Proceed from end
                    }
                }
                
                if ctx.signal == Signal::Continue {
                    ctx.signal = Signal::None; 
                    // Just proceed, the logic below handles the increment
                }

                // 3. Execution Logic
                let raw_count = instr.args.get(0).expect("Repeat requires a count");
                let resolved_count = resolve_vars(raw_count, ctx);
                let count: usize = resolved_count.trim().parse().unwrap_or(1);

                let var_name = instr.args.get(2).map(|s| s.replace("$", ""));
                let loop_key = format!("loop_{}", ctx.pc);

                let current_val = ctx.variables.entry(loop_key.clone())
                    .or_insert("0".to_string())
                    .parse::<usize>().unwrap_or(0);

                if current_val >= count {
                    ctx.loop_stack.pop(); // Loop finished naturally
                    if let Some(end_pos) = instr.jump_to {
                        ctx.pc = end_pos;
                        ctx.variables.remove(&loop_key);
                        if let Some(name) = var_name { ctx.variables.remove(&name); }
                    }
                } else {
                    let next_val = current_val + 1;
                    ctx.variables.insert(loop_key, next_val.to_string());
                    if let Some(name) = var_name {
                        ctx.variables.insert(name, (next_val - 1).to_string());
                    }
                }
            }
            "if" => {
                let is_true = evaluate(&instr.args, ctx).as_boolean().unwrap_or(false);
                if !is_true {
                    if let Some(target) = instr.jump_to {
                        ctx.pc = target + 1; 
                        continue; 
                    }
                }
            }
            "else" => {
                // If we hit an 'else' during normal execution, it means the 'if' body 
                // just finished. We need to skip the else block.
                if let Some(end_pos) = instr.jump_to {
                    ctx.pc = end_pos;
                    continue;
                }
            }
            "end" => {
                // 1. Handle Loops (Repeat)
                // If jump_to exists, the Linker (Pass 2) marked this as a backward jump.
                if let Some(target) = instr.jump_to {
                    ctx.pc = target;
                    continue;
                }

                // 2. Handle Function Returns
                if !ctx.return_stack.is_empty() {
                    // We only pop if we hit an explicit 'return' signal 
                    // OR we are at the physical end of the function (no more code in func).
                    if let Some(saved_pc) = ctx.return_stack.pop() {
                        ctx.pc = saved_pc;
                        ctx.signal = Signal::None; // Clear return signal
                        continue; // This returns us to the instruction AFTER 'call'
                    }
                }
                
                // 3. If it's an 'if' end, just fall through (pc += 1) 
                // This lets us reach: set $$person "brozo"
            }
            "exit" => std::process::exit(0),
            _ => {
                if ctx.corefuncs.contains(&instr.name) {
                    let name = &instr.name;
                    if let Some(&target_pc) = ctx.functions.get(name) {
                        let mut vals = Vec::new();
                        for arg in instr.args.iter().skip(0) {
                            vals.push(resolve_vars(arg, ctx));
                        }
                        ctx.arg_stack.push(vals);
                        
                        // Save the address to return to (the instruction AFTER call)
                        ctx.return_stack.push(ctx.pc + 1); 
                        
                        ctx.pc = target_pc;
                        continue; // Jump immediately to the 'func' line
                    }
                } else if &instr.name == "coreadd" {} else {
                    ctx.report_error(format!("unknown command: {}", instr.name).as_str(), instr.line_num);
                }
            }
        }

        ctx.pc += 1; // Move to next instruction
    }
}