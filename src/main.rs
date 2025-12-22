use std::env;
use colored::{ColoredString, Colorize};
use std::fs;
use std::path::PathBuf;
use std::collections::HashMap;
use evalexpr::{HashMapContext, Value, eval_with_context, ContextWithMutableVariables};

fn main() {
    let mut args: Vec<String> = env::args().collect();
    
    // 1. Detect and remove flags
    let verbose = args.iter().any(|arg| arg == "-v" || arg == "--verbose");
    let reverse = args.iter().any(|arg| arg == "-r" || arg == "--reverse");
    
    // Remove flags from the vector so they don't interfere with path/script args
    args.retain(|arg| !arg.starts_with('-'));

    // 2. Decide mode based on remaining args
    if args.len() < 2 {
        // Pass flags into your mode handler
        mode("interactive", &args, verbose, reverse);
        return;
    }
    
    mode("script", &args, verbose, reverse);
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
    pub pc: usize,

    pub functions: HashMap<String, usize>,
    pub return_stack: Vec<usize>,
    pub arg_stack: Vec<Vec<String>>,
    pub script_path: String,

    pub verbose: bool,
    pub reverse: bool,
}

impl Context {
    fn report_error(&self, msg: &str, line_num: usize) {
        let path = self.variables.get("script_path").unwrap_or(&self.script_path);
        eprintln!("{} {}:{} {}", "[xeo] err:".red(), path, line_num.to_string().as_str(), msg);
    }
}

struct Token {
    val: String,
    line: usize,
}

//================================//
//------- helper functions -------//
//================================//
fn printc(text: ColoredString) {
    println!("{}", text);
}

fn resolve_vars(text: &str, ctx: &Context) -> String {
    let mut result = text.to_string();
    // We iterate through our variables and replace instances of $name with the value
    for (name, value) in &ctx.variables {
        let placeholder = format!("${}", name);
        if result.contains(&placeholder) {
            result = result.replace(&placeholder, value);
        }
    }
    result
}

fn evaluate(args: &[String], ctx: &Context) -> Value {
    let expr = args.join(" ").replace('$', "");
    
    // Create a context for evalexpr
    let mut eval_ctx = HashMapContext::new();
    for (name, val) in &ctx.variables {
        // Feed your Xeo variables into the evaluator
        if let Ok(n) = val.parse::<f64>() {
            let _ = eval_ctx.set_value(name.into(), Value::Float(n));
        } else {
            let _ = eval_ctx.set_value(name.into(), Value::String(val.clone()));
        }
    }

    eval_with_context(&expr, &eval_ctx).unwrap_or(Value::from(false))
}

fn verbose_log(ctx: &Context, msg: &str) {
    if ctx.verbose {
        println!("{} {}", "[xeo] dbg:".cyan(), msg);
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
            println!("{}", &format!("failed to read xeo script: {}", e));
            Vec::new()
        }
    }
}

fn mode(mode: &str, args: &Vec<String>, verbose: bool, reverse: bool) {
    // Create one context that lives as long as the mode
    let mut ctx = Context {
        variables: HashMap::new(),
        pc: 0,
        functions: HashMap::new(),
        return_stack: Vec::new(),
        arg_stack: Vec::new(),
        script_path: Some(args[1].clone()).unwrap_or(String::from("error.xeo")),
        verbose,
        reverse,
    };
    let script_path = PathBuf::from(&args[1]);

    match mode {
        "interactive" => {
            printc("xeo v4.0.0 (interactive)".blue());
            loop {
                use std::io::{self, Write};
                print!("{}", ">> ".blue());
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
    let commands = ["print", "set", "if", "else", "end", "repeat", "func", "call", "wget", "fetch"];

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
        .for_each(|(idx, mut instr)| {
            instr.line_num = idx + 1; // Simple line number assignment
            program.push(instr);
        });

    // PASS 2: The Linker (Matches repeat with end)
    for i in 0..program.len() {
        match program[i].name.as_str() {
            "repeat" | "if" => {
                stack.push(i);
            }
            "func" => {
                let func_name = program[i].args[0].clone();
                ctx.functions.insert(func_name, i);
                stack.push(i);
            }
            "else" => {
                if let Some(if_index) = stack.pop() {
                    program[if_index].jump_to = Some(i); // if jumps to else
                    stack.push(i); // else now needs to find end
                } else {
                    ctx.report_error("stray 'else' found: no opening 'if'", program[i].line_num);
                }
            }
            "end" => {
                if let Some(start_index) = stack.pop() {
                    let parent_name = &program[start_index].name;

                    if parent_name == "func" {
                        if let Some(return_pc) = ctx.return_stack.pop() {
                            ctx.pc = return_pc + 1; // Go to the line AFTER the 'call'
                            continue; // IMPORTANT: Skip the default pc += 1
                        }
                    }

                    // Link the current 'end' to the parent (if, else, repeat, or func)
                    program[start_index].jump_to = Some(i);
                    program[i].jump_to = Some(start_index);

                } else {
                    ctx.report_error("stray 'end' found: no opening 'if', 'repeat', or 'func'", program[i].line_num);
                }
            }
            _ => {}
        }
    }
    
    // Check if any repeats were left unclosed
    for open_loop in stack {
        println!("Error: 'repeat' on line {} never ended", program[open_loop].line_num);
    }

    program
}

//================================//
//--------- interpreter ----------//
//================================//
fn execute(program: Vec<Instruction>, ctx: &mut Context) {
    while ctx.pc < program.len() {
        let instr = &program[ctx.pc];

        match instr.name.as_str() {
            "print" => {
                let output = resolve_vars(clean_multiline(&instr.args.join(" ")).as_str(), ctx);
                println!("{}", output);
            },

            "set" => {
                let var_name = instr.args[0].trim_start_matches('$').to_string();
                // Everything after the variable name is part of the expression
                let expression_parts = &instr.args[1..];
                
                // 1. Resolve all parts first (convert $vars to their values)
                let resolved_parts: Vec<String> = expression_parts.iter()
                    .map(|p| resolve_vars(p, ctx))
                    .collect();

                // 2. Determine if it's Math or String Concatenation
                let full_expr = resolved_parts.join(" ");
                
                // Logic: If it contains quotes or no math operators, it's a string
                let is_math = !full_expr.contains('"') && 
                            full_expr.chars().any(|c| "+-*/%()".contains(c));

                if is_math {
                    match evalexpr::eval(&full_expr) {
                        Ok(value) => {
                            ctx.variables.insert(var_name, value.to_string());
                        }
                        Err(_) => {
                            // If math fails, fallback to treating it as a literal string
                            ctx.variables.insert(var_name, full_expr);
                        }
                    }
                } else {
                    // 3. String Concatenation (Simply join without the "+" signs)
                    let mut final_str = String::new();
                    for part in resolved_parts {
                        if part != "+" { // Skip the '+' for string mode
                            final_str.push_str(&part.replace('"', "")); // Strip quotes for storage
                        }
                    }
                    ctx.variables.insert(var_name, final_str);
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

            "func" => {
                // If we are NOT in a function call (arg_stack is empty), 
                // it means the interpreter just 'walked' into this block.
                // We must jump to the 'end' to avoid running function code randomly.
                if ctx.arg_stack.is_empty() {
                    if let Some(end_pos) = instr.jump_to {
                        ctx.pc = end_pos;
                        continue; 
                    }
                }

                // Existing logic: map args to variables...
                if let Some(passed_values) = ctx.arg_stack.pop() {
                    // Skip the first arg (function name) and map the rest
                    for (i, val_name) in instr.args.iter().skip(1).enumerate() {
                        if let Some(val) = passed_values.get(i) {
                            ctx.variables.insert(val_name.trim_start_matches('$').to_string(), val.clone());
                        }
                    }
                }
            }

            "call" => {
                let name = &instr.args[0];
                if let Some(&target_pc) = ctx.functions.get(name) {
                    // 1. Collect arguments
                    let mut vals = Vec::new();
                    for arg in instr.args.iter().skip(1) {
                        vals.push(resolve_vars(arg, ctx));
                    }
                    
                    // 2. Push to stacks
                    ctx.arg_stack.push(vals);
                    ctx.return_stack.push(ctx.pc); // Save current position to come back
                    
                    // 3. Jump!
                    ctx.pc = target_pc;
                    continue; // Skip the standard pc += 1
                } else {
                    ctx.report_error(&format!("Function '{}' not found", name), instr.line_num);
                }
            }
            
            "repeat" => {
                // args[0] is "3", args[1] is "as", args[2] is "$n"
                let count: usize = instr.args.get(0).and_then(|s| s.parse().ok()).unwrap_or(1);
                
                // Check if the user defined a variable name (the "as $n" part)
                let var_name = instr.args.get(2).map(|s| s.replace("$", ""));

                let loop_key = format!("loop_{}", ctx.pc);
                let current_val = ctx.variables.entry(loop_key.clone())
                    .or_insert("0".to_string())
                    .parse::<usize>().unwrap_or(0);

                if current_val >= count {
                    // Exit loop
                    if let Some(end_pos) = instr.jump_to {
                        ctx.pc = end_pos;
                        ctx.variables.remove(&loop_key);
                        if let Some(name) = var_name { ctx.variables.remove(&name); }
                    }
                } else {
                    // Increment and set the user's variable
                    let next_val = current_val + 1;
                    ctx.variables.insert(loop_key, next_val.to_string());
                    
                    if let Some(name) = var_name {
                        ctx.variables.insert(name, next_val.to_string());
                    }
                }
            }

            "if" => {
                let is_true = evaluate(&instr.args, ctx); // Your evalexpr logic
                let is_true = match is_true {
                    Value::Boolean(b) => b,
                    Value::Float(f) => f != 0.0,
                    Value::Int(i) => i != 0,
                    Value::String(s) => !s.is_empty(),
                    _ => false,
                };
                if !is_true {
                    if let Some(target) = instr.jump_to {
                        ctx.pc = target; 
                    }
                }
            },

            "else" => {
                // If we hit this, the 'if' part was executed. 
                // We must skip the else-body and go to 'end'.
                if let Some(end_index) = instr.jump_to {
                    ctx.pc = end_index;
                }
            },

            "end" => {
                if let Some(start_index) = instr.jump_to {
                    let parent_type = &program[start_index].name;

                    if parent_type == "repeat" {
                        ctx.pc = start_index; // Loop back
                        continue; 
                    } 
                    
                    if parent_type == "func" {
                        // 5. RETURN: Look at the breadcrumb and go home
                        if let Some(return_to) = ctx.return_stack.pop() {
                            ctx.pc = return_to;
                            // No 'continue' here, so the next line of the loop 
                            // will do pc += 1 and put us right after the 'call'
                        }
                    }
                }
            },

            _ => {
                println!("Unknown command: {}", instr.name);
            }
        }

        ctx.pc += 1; // Move to next instruction
    }
}