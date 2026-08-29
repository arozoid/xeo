mod context;
mod eval;
mod interpreter;
mod lexer;
mod parser;
mod pipe;

use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

use crate::context::{Context, Instruction, BLUE, ESC};

//================================//
//-------- entry point ----------//
//================================//
fn main() {
    let mut args: Vec<String> = env::args().collect();

    let verbose = args.iter().any(|arg| arg == "-v" || arg == "--verbose");
    let ultra_verbose = args.iter().any(|arg| arg == "-vv" || arg == "--trace" || arg == "--debug");
    let version = args.iter().any(|arg| arg == "-V" || arg == "--version");
    let pipe = args.iter().any(|arg| arg == "-p" || arg == "--pipe");

    let verbose = verbose || ultra_verbose;

    args.retain(|arg| !arg.starts_with('-'));

    if version {
        println!("{BLUE}the .xeo scripting lang{ESC}");
        println!("v4.0.0 snapshot 25w52e");
        return;
    } else if pipe {
        mode("pipe", &args, verbose, ultra_verbose);
        return;
    } else if args.len() < 2 {
        mode("pipe/ongoing", &args, verbose, ultra_verbose);
        return;
    }

    mode("script", &args, verbose, ultra_verbose);
}

//================================//
//---------- top-level ----------//
//================================//
fn mode(mode: &str, args: &Vec<String>, verbose: bool, ultra_verbose: bool) {
    let path_str = args.get(1).cloned().unwrap_or_default();
    let mut ctx = Context::new(path_str.clone(), verbose, ultra_verbose);
    let script_path = PathBuf::from(&path_str);

    match mode {
        "pipe" | "pipe/framed" => {
            ctx.framed = true;
            pipe::handle_pipe(io::stdin(), ctx);
        }
        "pipe/ongoing" => {
            pipe::handle_pipe(io::stdin(), ctx);
        }
        "script" => {
            ctx.program = read_xeo(&script_path, &mut ctx);
            ctx.pc = 0;
            interpreter::execute(&mut ctx);
        }
        _ => println!("unknown filename: {:?}", &script_path),
    }
}

fn read_xeo(path: &PathBuf, ctx: &mut Context) -> Vec<Instruction> {
    match fs::read_to_string(path) {
        Ok(content) => parser::parse(&content, ctx),
        Err(e) => {
            ctx.report_error(&format!("failed to read xeo script: {}", e), 0);
            Vec::new()
        }
    }
}

fn get_xeon_dir() -> PathBuf {
    #[cfg(windows)]
    let mut path = PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default());

    #[cfg(unix)]
    let mut path = PathBuf::from(std::env::var("HOME").unwrap_or_default());

    path.push(".xeon");
    path
}