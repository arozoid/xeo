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
        println!("for {} ({})", host_triple(), host_platform());
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
    seed_startup_args(&mut ctx, args);
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

fn seed_startup_args(ctx: &mut Context, args: &[String]) {
    let script_args = args.get(2..).unwrap_or(&[]);

    ctx.variables.insert("ARGC".to_string(), script_args.len().to_string());
    ctx.variables.insert("ARGS".to_string(), script_args.join(" "));

    for (index, value) in script_args.iter().enumerate() {
        ctx.variables.insert(format!("ARG{}", index + 1), value.clone());
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

//================================//
//----- host architecture --------//
//================================//
/// normalized CPU architecture: `x86_64`, `arm64`, else `uname -m`
fn host_arch() -> String {
    let raw = uname_m().unwrap_or_else(|| "unknown".to_string());
    match raw.as_str() {
        "x86_64" | "amd64" => "x86_64".to_string(),
        "aarch64" | "arm64" => "arm64".to_string(),
        other => other.to_string(),
    }
}

/// normalized operating system: `linux`, `windows`, `macos`, else the os name
fn host_platform() -> String {
    match std::env::consts::OS {
        "linux" => "linux".to_string(),
        "windows" => "windows".to_string(),
        "macos" => "macos".to_string(),
        other => other.to_string(),
    }
}

/// rust-style target triple for the host (e.g. `x86_64-linux-x86_64`)
fn host_triple() -> String {
    format!("{}-{}-{}", host_arch(), host_platform(), std::env::consts::ARCH)
}

fn uname_m() -> Option<String> {
    let out = std::process::Command::new("uname").arg("-m").output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}
