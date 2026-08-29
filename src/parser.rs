use crate::context::{Context, Instruction};
use crate::lexer::{Token, lex};

// Every statement-start token becomes an instruction. The interpreter resolves
// it: known commands run directly, function names registered via coreadd
// dispatch to their function, and anything else is reported as an error. This
// is what lets a script call a coreadd'd function declared later at runtime.
fn parse_tokens(tokens: Vec<Token>) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut i = 0;

    while i < tokens.len() {
        let name = tokens[i].val.clone();
        let line_num = tokens[i].line;

        i += 1;
        let mut args = Vec::new();
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
    }
    instructions
}

pub fn parse(content: &str, ctx: &mut Context) -> Vec<Instruction> {
    let mut program = Vec::new();
    let mut stack = Vec::new();
    let tokens = lex(content);

    // PRE-PASS: scan for coreadd function names
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i].val == "coreadd" {
            if let Some(name_token) = tokens.get(i + 1) {
                ctx.corefuncs.push(name_token.val.clone());
            }
        }
        i += 1;
    }

    // PASS 1: build the instructions
    parse_tokens(tokens)
        .into_iter()
        .for_each(|instr| {
            program.push(instr);
        });

    // PASS 2: linked blocks (if/repeat/func .. end)
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
                    program[if_idx].jump_to = Some(i);
                    stack.push(i);
                }
            }
            "end" => {
                if let Some(start_idx) = stack.pop() {
                    let parent = program[start_idx].name.clone();
                    program[start_idx].jump_to = Some(i);

                    if parent == "repeat" {
                        program[i].jump_to = Some(start_idx);
                    } else {
                        program[i].jump_to = None;
                    }
                }
            }
            _ => {}
        }
    }

    for open_loop in stack {
        ctx.report_error("'repeat' on line {} never ended", program[open_loop].line_num);
    }

    program
}