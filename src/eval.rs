use crate::context::Context;

#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Float(f64),
    Bool(bool),
    Str(String),
}

impl Val {
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            Val::Bool(b) => Some(*b),
            Val::Str(s) => Some(s == "true"),
            _ => None,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            Val::Float(f) => f.to_string(),
            Val::Bool(b) => b.to_string(),
            Val::Str(s) => s.clone(),
        }
    }
}

const MATH_ATOMS: &[&str] = &[
    "==", "!=", ">=", "<=", "&&", "||", "+", "-", "*", "/", "%", "^", "(", ")",
    "true", "false",
];

// Decide whether a `set`/`let` expression is arithmetic. Every atom must be a
// numeric literal, an operator/bool, or a variable holding a number.
pub fn is_math_expr(parts: &[String], ctx: &Context) -> bool {
    let mut has_op = false;
    for part in parts {
        if part.is_empty() {
            continue;
        }
        if MATH_ATOMS.contains(&part.as_str()) {
            if matches!(part.as_str(), "+" | "-" | "*" | "/" | "%" | "^" | "==" | "!=" | ">=" | "<=" | "&&" | "||" | "(" | ")") {
                has_op = true;
            }
            continue;
        }
        // tolerate single tokens that bundle parens, e.g. "(10" or "5)"
        let mut t: &str = part;
        while let Some(stripped) = t.strip_prefix('(') { t = stripped; }
        while let Some(stripped) = t.strip_suffix(')') { t = stripped; }
        if t.parse::<f64>().is_ok() {
            continue;
        }
        if let Some(name) = t.strip_prefix('$') {
            let v = ctx.variables.get(name)
                .or_else(|| ctx.variables.get(&format!("${}", name)))
                .cloned()
                .unwrap_or_default();
            if v.trim().parse::<f64>().is_ok() {
                continue;
            }
        }
        return false; // a non-numeric atom => treat the whole thing as a string
    }
    has_op
}

pub fn evaluate(args: &[String], ctx: &Context) -> Val {
    let raw_expr = args.join(" ");
    let resolved_expr = ctx.resolve(&raw_expr);

    let tokens = tokenize(&resolved_expr);
    let rpn = to_rpn(tokens);
    solve_rpn(rpn)
}

fn tokenize(expr: &str) -> Vec<String> {
    let mut s = expr.to_string();
    let ops = ["==", "!=", ">=", "<=", "&&", "||", "+", "-", "*", "/", "(", ")", "<", ">", "%", "^"];

    for op in ops {
        s = s.replace(op, &format!(" {} ", op));
    }

    s.split_whitespace().map(|s| s.to_string()).collect()
}

fn to_rpn(tokens: Vec<String>) -> Vec<String> {
    let mut output_queue = Vec::new();
    let mut op_stack = Vec::new();

    for token in tokens {
        if let Ok(_) = token.parse::<f64>() {
            output_queue.push(token);
        } else if token == "true" || token == "false" || token.starts_with('"') {
            output_queue.push(token);
        } else if token == "(" {
            op_stack.push(token);
        } else if token == ")" {
            while let Some(top) = op_stack.pop() {
                if top == "(" { break; }
                output_queue.push(top);
            }
        } else {
            while let Some(top) = op_stack.last() {
                if top == "(" || precedence(top) < precedence(&token) { break; }
                output_queue.push(op_stack.pop().unwrap());
            }
            op_stack.push(token);
        }
    }

    while let Some(op) = op_stack.pop() {
        output_queue.push(op);
    }
    output_queue
}

fn solve_rpn(rpn: Vec<String>) -> Val {
    let mut stack: Vec<Val> = Vec::new();

    for token in rpn {
        if let Ok(n) = token.parse::<f64>() {
            stack.push(Val::Float(n));
        } else if let Ok(b) = token.parse::<bool>() {
            stack.push(Val::Bool(b));
        } else if token.starts_with('"') {
            stack.push(Val::Str(token.trim_matches('"').to_string()));
        } else {
            let b = stack.pop().unwrap_or(Val::Float(0.0));
            let a = stack.pop().unwrap_or(Val::Float(0.0));
            let res = apply_op(&token, a, b);
            stack.push(res);
        }
    }

    stack.pop().unwrap_or(Val::Bool(false))
}

fn precedence(op: &str) -> u8 {
    match op {
        "||" => 1,
        "&&" => 2,
        "==" | "!=" => 3,
        "<" | ">" | "<=" | ">=" => 4,
        "+" | "-" => 5,
        "*" | "/" | "%" => 6,
        "^" => 7,
        _ => 0,
    }
}

fn apply_op(op: &str, a: Val, b: Val) -> Val {
    let get_nums = |v1: &Val, v2: &Val| -> (f64, f64) {
        let n1 = match v1 { Val::Float(f) => *f, _ => 0.0 };
        let n2 = match v2 { Val::Float(f) => *f, _ => 0.0 };
        (n1, n2)
    };

    let get_bools = |v1: &Val, v2: &Val| -> (bool, bool) {
        let b1 = match v1 { Val::Bool(b) => *b, _ => false };
        let b2 = match v2 { Val::Bool(b) => *b, _ => false };
        (b1, b2)
    };

    match op {
        "+" => { let (x, y) = get_nums(&a, &b); Val::Float(x + y) },
        "-" => { let (x, y) = get_nums(&a, &b); Val::Float(x - y) },
        "*" => { let (x, y) = get_nums(&a, &b); Val::Float(x * y) },
        "/" => { let (x, y) = get_nums(&a, &b); Val::Float(x / y) },
        "%" => { let (x, y) = get_nums(&a, &b); Val::Float(x % y) },
        "^" => { let (x, y) = get_nums(&a, &b); Val::Float(x.powf(y)) },

        "==" => match (a, b) {
            (Val::Float(x), Val::Float(y)) => Val::Bool(x == y),
            (Val::Bool(x), Val::Bool(y)) => Val::Bool(x == y),
            (Val::Str(x), Val::Str(y)) => Val::Bool(x == y),
            _ => Val::Bool(false),
        },
        "!=" => match (a, b) {
            (Val::Float(x), Val::Float(y)) => Val::Bool(x != y),
            (Val::Bool(x), Val::Bool(y)) => Val::Bool(x != y),
            (Val::Str(x), Val::Str(y)) => Val::Bool(x != y),
            _ => Val::Bool(true),
        },
        ">" => { let (x, y) = get_nums(&a, &b); Val::Bool(x > y) },
        "<" => { let (x, y) = get_nums(&a, &b); Val::Bool(x < y) },
        ">=" => { let (x, y) = get_nums(&a, &b); Val::Bool(x >= y) },
        "<=" => { let (x, y) = get_nums(&a, &b); Val::Bool(x <= y) },

        "&&" => { let (x, y) = get_bools(&a, &b); Val::Bool(x && y) },
        "||" => { let (x, y) = get_bools(&a, &b); Val::Bool(x || y) },

        _ => Val::Bool(false),
    }
}