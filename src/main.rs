use std::env;
use std::fs;
use std::path::PathBuf;
use std::collections::HashMap;
use std::io::{self, Write};
use evalexpr::{HashMapContext, Value, eval_with_context, ContextWithMutableVariables};

fn main() {
    let mut args: Vec<String> = env::args().collect();
    
    // 1. Detect and remove flags
    let verbose = args.iter().any(|arg| arg == "-v" || arg == "--verbose");
    let ultra_verbose = args.iter().any(|arg| arg == "-vv" || arg == "--trace" || arg == "--debug");
    let reverse = args.iter().any(|arg| arg == "-r" || arg == "--reverse");
    let version = args.iter().any(|arg| arg == "-V" || arg == "--version");

    let verbose = verbose || ultra_verbose;
    println!("{}", ultra_verbose);
    
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
    pub pc: usize,
    
    pub script_path: String,
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
const GREEN: &str = "\x1b[32m";
const BLUE: &str = "\x1b[34m";
const DIM: &str = "\x1b[2m";
const ESC: &str = "\x1b[0m";

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
        script_path: path_str.clone(),

        pc: 0,
        ultra_verbose,
        verbose,
        reverse,
    };
    let script_path = PathBuf::from(&path_str);

    match mode {
        "interactive" => {
            println!("{BLUE}xeo v4.0.0 (interactive){ESC}");
            loop {
                use std::io::{self, Write};
                print!("{BLUE}>> {ESC}");
                io::stdout().flush().unwrap();

                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                
                if input.trim() == "exit" { break; }

                // 1. Parse the input into instructions
                let program = parse(&input, &mut ctx);
                
                // 2. Reset PC for this specific snippet and run
                ctx.pc = 0; 
                execute(program, &mut ctx);
            }
        }
        "script" => {
            // 1. Load and Parse the whole file
            let program = read_xeo(&script_path, &mut ctx);
            
            // 2. Run the whole program
            ctx.pc = 0;
            execute(program, &mut ctx);
        }
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
    let mut token_start_line = 1;
    let mut chars = content.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\n' { line_count += 1; }

        if current.is_empty() && !c.is_whitespace() {
            token_start_line = line_count;
        }

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
                if !in_quotes { token_start_line = line_count; }
                in_quotes = !in_quotes; 
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(Token { val: current.clone(), line: line_count });
                    current.clear();
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(Token { val: current, line: token_start_line });
    }
    tokens
}

fn parse_tokens(tokens: Vec<Token>) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut i = 0;
    let commands = ["print", "set", "continue", "return", "break", "if", "else", "end", "repeat", "func", "call", "wget", "fetch", "wait", "exit", "ask"];

    while i < tokens.len() {
        if commands.contains(&tokens[i].val.as_str()) {
            let name = tokens[i].val.clone();
            let line_num = tokens[i].line; // Capture the actual line!
            i += 1;

            let mut args = Vec::new();
            while i < tokens.len() && !commands.contains(&tokens[i].val.as_str()) {
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

    // PASS 1: Create the instructions
    parse_tokens(lex(content))
        .into_iter()
        .enumerate()
        .for_each(|(_idx, mut instr)| {
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
fn execute(program: Vec<Instruction>, ctx: &mut Context) {
    while ctx.pc < program.len() {
        let instr = &program[ctx.pc];

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
            "print" => {
                let output = resolve_vars(clean_multiline(&instr.args.join(" ")).as_str(), ctx);
                println!("{}", output);
            }
            "ask" => {
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
                if let Ok(response) = minreq::get(url).send() {
                    let body = response.as_str().unwrap_or("");
                    ctx.variables.insert("res".to_string(), body.to_string());
                }
            }
            "wget" => {
                let path = resolve_vars(&instr.args[1], ctx);

                if ctx.reverse {
                    // UNDO: Delete the file
                    verbose_log(ctx, &format!("rollback: deleting {}", path));
                    if std::path::Path::new(&path).exists() {
                        if let Err(e) = std::fs::remove_file(&path) {
                            ctx.report_error(&format!("failed to delete {}: {}", path, e), instr.line_num);
                        }
                    }
                } else {
                    // DO: Download the file
                    let url = resolve_vars(&instr.args[0], ctx);
                    verbose_log(ctx, &format!("downloading {} to {}", url, path));
                    match minreq::get(&url).send() {
                        Ok(res) => { std::fs::write(&path, res.as_bytes()).ok(); }
                        Err(e) => ctx.report_error(&format!("wget failed: {}", e), instr.line_num),
                    }
                }
            }
            //================//
            //---core stuff---//
            //================//
            "coreadd" => {
                let func_name = instr.args.get(0).expect("error finding args");
                if func_name == "" {
                    ctx.report_error("coreadd requires a command", instr.line_num);
                } else if func_name == "error finding args" {
                    ctx.report_error("was unable to parse coreadd args", instr.line_num);
                } else {
                    ctx.corefuncs.push(func_name.to_string());
                }
            }
            "wait" => {
                std::thread::sleep(std::time::Duration::from_millis(instr.args.get(0).expect("invalid sleep time").parse::<u64>().unwrap()));
            }
            "set" => {
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
            "func" => {
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
            "call" => {
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
                        for arg in instr.args.iter().skip(1) {
                            vals.push(resolve_vars(arg, ctx));
                        }
                        ctx.arg_stack.push(vals);
                        
                        // Save the address to return to (the instruction AFTER call)
                        ctx.return_stack.push(ctx.pc + 1); 
                        
                        ctx.pc = target_pc;
                        continue; // Jump immediately to the 'func' line
                    }
                } else {
                    ctx.report_error(format!("unknown command: {}", instr.name).as_str(), instr.line_num);
                }
            }
        }

        ctx.pc += 1; // Move to next instruction
    }
}