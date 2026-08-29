use std::io::{self, Stdin, Write};
use std::io::BufRead;

use crate::context::{Context, Signal};
use crate::interpreter::execute;
use crate::lexer::is_block_complete;
use crate::parser::parse;

pub fn handle_pipe(stdin: Stdin, mut ctx: Context) {
    let mut handle = stdin.lock();
    let mut accumulator = String::new();
    let mut line = String::new();

    let framed = ctx.framed;
    let request_flush = |acc: &str, is_blank: bool| -> bool {
        if is_blank { return true; }
        if !framed && is_block_complete(acc) { return true; }
        false
    };

    loop {
        line.clear();
        if handle.read_line(&mut line).unwrap() == 0 {
            if !accumulator.trim().is_empty() {
                run_request(&mut ctx, &accumulator);
            }
            break;
        }

        let is_blank = line.trim().is_empty();

        if is_blank && accumulator.trim().is_empty() {
            continue;
        }

        accumulator.push_str(&line);

        if request_flush(&accumulator, is_blank) {
            run_request(&mut ctx, &accumulator);
            accumulator.clear();
        }
    }
}

// Parse + rebase + append a chunk of source into the persistent program.
// parse() computes jump targets and function indices relative to the chunk
// (0..len); rebase them onto the global program and return the new program len.
pub fn append_program(ctx: &mut Context, content: &str) -> usize {
    let start = ctx.program.len();
    let mut new_instrs = parse(content, ctx);

    for instr in &mut new_instrs {
        if let Some(j) = instr.jump_to {
            instr.jump_to = Some(j + start);
        }
    }
    for (i, instr) in new_instrs.iter().enumerate() {
        if matches!(instr.name.as_str(), "func" | "def" | "function") {
            if let Some(name) = instr.args.first() {
                ctx.functions.insert(name.clone(), start + i);
            }
        }
    }

    let total = ctx.program.len() + new_instrs.len();
    ctx.program.extend(new_instrs);
    total
}

fn run_request(ctx: &mut Context, accumulator: &str) {
    let input = accumulator.trim();
    if input.is_empty() {
        return;
    }

    ctx.signal = Signal::None;
    ctx.out_buffer.clear();
    ctx.errs.clear();

    let start = ctx.program.len();
    let total = append_program(ctx, input);
    ctx.pc = start;
    execute(ctx);

    ctx.pc = total;

    if ctx.framed {
        flush_response(ctx);
    } else {
        io::stdout().flush().ok();
    }
}

// Frame + emit one request's response, ending with the DONE sentinel so the
// host knows where one interaction's output ends.
fn flush_response(ctx: &mut Context) {
    let stdout = std::mem::take(&mut ctx.out_buffer);
    let errs = std::mem::take(&mut ctx.errs);

    let mut out = io::stdout().lock();
    out.write_all(stdout.as_bytes()).ok();
    for e in &errs {
        writeln!(out, "ERR: {e}").ok();
    }
    writeln!(out, "__XEO_DONE__").ok();
    out.flush().ok();
}