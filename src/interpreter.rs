use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;

use crate::context::{Context, Instruction, Signal, BLUE, DIM, ESC};
use crate::eval::{evaluate, is_math_expr};
use crate::lexer::clean_multiline;
use crate::pipe::append_program;
use crate::get_xeon_dir;

enum Flow {
    Next,
    Jump(usize),
    Stop,
}

pub fn execute(ctx: &mut Context) {
    while ctx.pc < ctx.program.len() {
        let is_function_end = ctx.program[ctx.pc].name == "end" && ctx.program[ctx.pc].jump_to.is_none();
        if ctx.signal == Signal::Return && !is_function_end {
            ctx.pc += 1;
            continue;
        }

        if ctx.ultra_verbose {
            verbose_log(ctx, &format!("{} {DIM}({}:{}){ESC}",
                ctx.program[ctx.pc].name, ctx.script_path, ctx.program[ctx.pc].line_num));
        }

        let instr = ctx.program[ctx.pc].clone();
        match dispatch(ctx, &instr) {
            Flow::Jump(pc) => ctx.pc = pc,
            Flow::Stop => break,
            Flow::Next => ctx.pc += 1,
        }
    }
}

fn emit_out(ctx: &mut Context, s: &str) {
    if ctx.framed {
        ctx.out_buffer.push_str(s);
        ctx.out_buffer.push('\n');
    } else {
        println!("{s}");
    }
}

fn verbose_log(ctx: &mut Context, msg: &str) {
    if ctx.verbose {
        emit_out(ctx, &format!("{BLUE}[xeo] dbg: {ESC}{msg}"));
    }
}

fn dispatch(ctx: &mut Context, instr: &Instruction) -> Flow {
    match instr.name.as_str() {
        "print" => handle_print(ctx, instr),
        "ask" | "input" => handle_ask(ctx, instr),
        "find" => handle_find(ctx, instr),
        "get" => handle_get(ctx, instr),
        "ext" | "extc" => handle_ext(ctx, instr),
        "use" | "import" => handle_use(ctx, instr),
        "wait" | "sleep" => handle_wait(instr),
        "set" | "let" => handle_set(ctx, instr),
        "break" => handle_break(ctx, instr),
        "continue" => handle_continue(ctx, instr),
        "return" => handle_return(ctx, instr),
        "func" | "def" | "function" => handle_func(ctx, instr),
        "run" | "call" => handle_run(ctx, instr),
        "repeat" => handle_repeat(ctx, instr),
        "if" => handle_if(ctx, instr),
        "else" => handle_else(instr),
        "end" => handle_end(ctx, instr),
        "exit" => process::exit(0),
        _ => handle_custom(ctx, instr),
    }
}

// Push resolved params, save the return address, jump to the function body.
fn call_function(ctx: &mut Context, name: &str, params: Vec<String>) -> Flow {
    if let Some(&target_pc) = ctx.functions.get(name) {
        ctx.arg_stack.push(params);
        ctx.return_stack.push(ctx.pc + 1);
        return Flow::Jump(target_pc);
    }
    Flow::Next
}

fn handle_print(ctx: &mut Context, instr: &Instruction) -> Flow {
    let output = ctx.resolve(&clean_multiline(&instr.args.join(" ")));
    emit_out(ctx, &output);
    Flow::Next
}

fn handle_ask(ctx: &mut Context, instr: &Instruction) -> Flow {
    let prompt = instr.args.get(1).map(|s| s.as_str()).unwrap_or("> ");
    print!("{}", prompt);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_n) => {
            let var_name = instr.args.get(0)
                .expect("$var missing")
                .trim_start_matches('$')
                .to_string();
            ctx.variables.insert(var_name, input.trim().to_string());
            verbose_log(ctx, &format!("user input: {}", input.trim()));
        }
        Err(e) => ctx.report_error(&format!("{}", e), instr.line_num),
    }
    Flow::Next
}

fn handle_find(ctx: &mut Context, instr: &Instruction) -> Flow {
    let haystack = ctx.resolve(&instr.args[0]);
    let needle = ctx.resolve(&instr.args[1]);
    let dest_var = instr.args[2].clone();
    let found = haystack.contains(&needle);
    ctx.variables.insert(dest_var, found.to_string());
    Flow::Next
}

fn handle_get(ctx: &mut Context, instr: &Instruction) -> Flow {
    let dynamic_name = ctx.resolve(&instr.args[0]);
    let value = ctx.variables.get(&dynamic_name).cloned().unwrap_or_default();
    ctx.variables.insert(instr.args[2].clone(), value);
    Flow::Next
}

fn find_module_path(raw_name: &str) -> Option<PathBuf> {
    let local_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let xeon_lib_dir = get_xeon_dir().join("lib");

    for dir in [local_dir, xeon_lib_dir] {
        let exact_path = dir.join(raw_name);
        if exact_path.is_file() {
            return Some(exact_path);
        }
        if !raw_name.ends_with(".xeo") {
            let with_ext = dir.join(format!("{raw_name}.xeo"));
            if with_ext.is_file() {
                return Some(with_ext);
            }
        }
    }
    None
}

fn handle_use(ctx: &mut Context, instr: &Instruction) -> Flow {
    let raw_name = ctx.resolve(&instr.args[0]);
    match find_module_path(&raw_name) {
        Some(path) => {
            let canon = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            let key = canon.to_string_lossy().into_owned();

            if !ctx.loaded_modules.insert(key.clone()) {
                verbose_log(ctx, &format!("module {:?} already loaded, skipping", path));
            } else {
                match fs::read_to_string(&path) {
                    Ok(content) => {
                        verbose_log(ctx, &format!("using: {:?}", path));

                        let saved_pc = ctx.pc;
                        let start = ctx.program.len();
                        append_program(ctx, &content);
                        ctx.pc = start;
                        execute(ctx);
                        ctx.pc = saved_pc;
                        ctx.signal = Signal::None;
                    }
                    Err(e) => ctx.report_error(&format!("failed to read module {:?}: {}", path, e), instr.line_num),
                }
            }
        }
        None => ctx.report_error(&format!("module '{}' not found in local dir or ~/.xeon/lib", raw_name), instr.line_num),
    }
    Flow::Next
}

fn handle_ext(ctx: &mut Context, instr: &Instruction) -> Flow {
    let is_capture = instr.name == "extc";
    let cmd_name = ctx.resolve(&instr.args[0]);
    let cmd_path = get_xeon_dir().join("bin").join(&cmd_name);

    if !cmd_path.exists() {
        ctx.report_error(&format!("command not found in xeon/bin: {}", cmd_name), instr.line_num);
        return Flow::Stop;
    }

    let cmd_args: Vec<String> = instr.args[1..].iter().map(|a| ctx.resolve(a)).collect();
    let mut command = process::Command::new(cmd_path);
    command.args(cmd_args);

    if is_capture {
        match command.output() {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                ctx.variables.insert("res".to_string(), stdout);
            }
            Err(e) => ctx.report_error(&format!("extc failed: {}", e), instr.line_num),
        }
    } else if ctx.framed {
        match command.output() {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if !stdout.trim().is_empty() {
                    ctx.out_buffer.push_str(&stdout);
                    if !stdout.ends_with('\n') { ctx.out_buffer.push('\n'); }
                }
            }
            Err(e) => ctx.report_error(&format!("ext failed: {}", e), instr.line_num),
        }
    } else {
        match command.spawn() {
            Ok(mut child) => { child.wait().ok(); }
            Err(e) => ctx.report_error(&format!("ext failed: {}", e), instr.line_num),
        }
    }
    Flow::Next
}

fn handle_wait(instr: &Instruction) -> Flow {
    let ms_str = instr.args.get(0).map(|s| s.as_str()).unwrap_or("0");
    if let Ok(mut remaining_ms) = ms_str.parse::<u64>() {
        while remaining_ms > 0 {
            let sleep_chunk = if remaining_ms > 100 { 100 } else { remaining_ms };
            std::thread::sleep(std::time::Duration::from_millis(sleep_chunk));
            remaining_ms -= sleep_chunk;
        }
    }
    Flow::Next
}

fn handle_set(ctx: &mut Context, instr: &Instruction) -> Flow {
    let var_name = if instr.args[0].starts_with("$$") {
        let pointer_name = &instr.args[0][2..];
        ctx.variables.get(pointer_name)
            .or_else(|| ctx.variables.get(&format!("${}", pointer_name)))
            .cloned()
            .unwrap_or_else(|| pointer_name.to_string())
    } else {
        instr.args[0].trim_start_matches('$').to_string()
    };

    let final_key = var_name.trim_start_matches('$').to_string();
    if final_key.is_empty() {
        return Flow::Stop;
    }

    let resolved_parts: Vec<String> = instr.args[1..].iter().map(|p| ctx.resolve(p)).collect();

    if is_math_expr(&resolved_parts, ctx) {
        let tokens: Vec<String> = resolved_parts.join(" ").split_whitespace().map(|s| s.to_string()).collect();
        let result = evaluate(&tokens, ctx);
        ctx.variables.insert(final_key, result.to_string());
    } else {
        let mut final_str = String::new();
        for part in resolved_parts {
            if part != "+" {
                final_str.push_str(&part.replace('"', ""));
            }
        }
        ctx.variables.insert(final_key, final_str);
    }
    Flow::Next
}

fn handle_break(ctx: &mut Context, _instr: &Instruction) -> Flow {
    ctx.signal = Signal::Break;
    match ctx.loop_stack.last() {
        Some(&loop_start) => Flow::Jump(loop_start),
        None => Flow::Next,
    }
}

fn handle_continue(ctx: &mut Context, _instr: &Instruction) -> Flow {
    ctx.signal = Signal::Continue;
    match ctx.loop_stack.last() {
        Some(&loop_start) => Flow::Jump(loop_start),
        None => Flow::Next,
    }
}

fn handle_return(ctx: &mut Context, _instr: &Instruction) -> Flow {
    ctx.signal = Signal::Return;
    Flow::Next
}

fn handle_func(ctx: &mut Context, instr: &Instruction) -> Flow {
    if ctx.arg_stack.is_empty() {
        if let Some(end_pos) = instr.jump_to {
            return Flow::Jump(end_pos + 1);
        }
    }

    if let Some(passed_values) = ctx.arg_stack.pop() {
        for (i, val_name) in instr.args.iter().skip(1).enumerate() {
            if let Some(val) = passed_values.get(i) {
                let key = val_name.trim_start_matches('$').to_string();
                ctx.variables.insert(key, val.clone());
            }
        }
    }
    Flow::Next
}

fn handle_run(ctx: &mut Context, instr: &Instruction) -> Flow {
    let params: Vec<String> = instr.args.iter().skip(1).map(|a| ctx.resolve(a)).collect();
    call_function(ctx, &instr.args[0], params)
}

fn handle_repeat(ctx: &mut Context, instr: &Instruction) -> Flow {
    if !ctx.loop_stack.contains(&ctx.pc) {
        ctx.loop_stack.push(ctx.pc);
    }

    if ctx.signal == Signal::Break {
        ctx.signal = Signal::None;
        ctx.loop_stack.pop();
        if let Some(end_pos) = instr.jump_to {
            return Flow::Jump(end_pos);
        }
    }

    if ctx.signal == Signal::Continue {
        ctx.signal = Signal::None;
    }

    let raw_count = instr.args.get(0).expect("Repeat requires a count");
    let resolved_count = ctx.resolve(raw_count);
    let count: usize = resolved_count.trim().parse().unwrap_or(1);

    let var_name = instr.args.get(2).map(|s| s.replace("$", ""));
    let loop_key = format!("loop_{}", ctx.pc);

    let current_val = ctx.variables.entry(loop_key.clone())
        .or_insert("0".to_string())
        .parse::<usize>().unwrap_or(0);

    if current_val >= count {
        ctx.loop_stack.pop();
        if let Some(end_pos) = instr.jump_to {
            ctx.variables.remove(&loop_key);
            if let Some(name) = var_name { ctx.variables.remove(&name); }
            return Flow::Jump(end_pos + 1);
        }
    } else {
        let next_val = current_val + 1;
        ctx.variables.insert(loop_key, next_val.to_string());
        if let Some(name) = var_name {
            ctx.variables.insert(name, (next_val - 1).to_string());
        }
    }
    Flow::Next
}

fn handle_if(ctx: &mut Context, instr: &Instruction) -> Flow {
    let is_true = evaluate(&instr.args, ctx).as_boolean().unwrap_or(false);
    if !is_true {
        if let Some(target) = instr.jump_to {
            return Flow::Jump(target + 1);
        }
    }
    Flow::Next
}

fn handle_else(instr: &Instruction) -> Flow {
    if let Some(end_pos) = instr.jump_to {
        return Flow::Jump(end_pos);
    }
    Flow::Next
}

fn handle_end(ctx: &mut Context, instr: &Instruction) -> Flow {
    if let Some(target) = instr.jump_to {
        return Flow::Jump(target);
    }

    if !ctx.return_stack.is_empty() {
        if let Some(saved_pc) = ctx.return_stack.pop() {
            ctx.signal = Signal::None;
            return Flow::Jump(saved_pc);
        }
    }

    Flow::Next
}

fn handle_custom(ctx: &mut Context, instr: &Instruction) -> Flow {
    if ctx.corefuncs.contains(&instr.name) {
        let params: Vec<String> = instr.args.iter().map(|a| ctx.resolve(a)).collect();
        return call_function(ctx, &instr.name, params);
    } else if instr.name != "coreadd" {
        ctx.report_error(&format!("unknown command: {}", instr.name), instr.line_num);
    }
    Flow::Next
}