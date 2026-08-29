use std::collections::{HashMap, HashSet};

pub const RED: &str = "\x1b[31m";
pub const BLUE: &str = "\x1b[34m";
pub const DIM: &str = "\x1b[2m";
pub const ESC: &str = "\x1b[0m";

#[derive(Debug, Clone)]
pub struct Instruction {
    pub name: String,
    pub args: Vec<String>,
    pub line_num: usize,
    pub jump_to: Option<usize>,
}

pub struct Context {
    pub variables: HashMap<String, String>,
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

    pub framed: bool,
    pub out_buffer: String,
    pub errs: Vec<String>,
}

impl Context {
    pub fn new(script_path: String, verbose: bool, ultra_verbose: bool) -> Context {
        Context {
            variables: HashMap::new(),
            functions: HashMap::new(),
            signal: Signal::None,
            corefuncs: Vec::new(),

            return_stack: Vec::new(),
            loop_stack: Vec::new(),
            arg_stack: Vec::new(),
            program: Vec::new(),
            pc: 0,

            script_path,
            loaded_modules: HashSet::new(),
            ultra_verbose,
            verbose,

            framed: false,
            out_buffer: String::new(),
            errs: Vec::new(),
        }
    }

    pub fn report_error(&mut self, msg: &str, line_num: usize) {
        let path = self.variables.get("script_path").cloned().unwrap_or_else(|| self.script_path.clone());
        let full = format!("{msg} ({path}:{line_num})");
        self.errs.push(full.clone());
        eprintln!("{RED}[xeo] err: {ESC}{msg} {DIM}({path}:{line_num}){ESC}");
    }

    // Sort keys by length descending so $element is replaced before $e
    pub fn resolve(&self, text: &str) -> String {
        let mut result = text.to_string();

        let mut keys: Vec<_> = self.variables.keys().collect();
        keys.sort_by_key(|k| std::cmp::Reverse(k.len()));

        for name in keys {
            let value = &self.variables[name];
            let placeholder = format!("${}", name.trim_start_matches('$'));
            if result.contains(&placeholder) {
                result = result.replace(&placeholder, value);
            }
        }
        result
    }
}

#[derive(PartialEq)]
pub enum Signal {
    None,
    Break,
    Continue,
    Return,
}