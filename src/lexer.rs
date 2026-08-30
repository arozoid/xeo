pub struct Token {
    pub val: String,
    pub line: usize,
}

pub fn lex(content: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut line_count = 1;
    let mut token_start_line = 1;
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
            '-' if !in_quotes => {
                if let Some(&next) = chars.peek() {
                    if next == '-' {
                        while let Some(&next) = chars.peek() {
                            if next == '\n' { break; }
                            chars.next();
                        }
                    } else {
                        current.push('-');
                    }
                } else {
                    current.push('-');
                }
            }
            '"' => {
                if !in_quotes {
                    token_start_line = line_count;
                }
                in_quotes = !in_quotes;
            }
            '\n' => {
                if in_quotes {
                    current.push('\n');
                } else {
                    if !current.is_empty() {
                        tokens.push(Token { val: current.clone(), line: token_start_line });
                        current.clear();
                    }
                }
                line_count += 1;
                if current.is_empty() {
                    token_start_line = line_count;
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(Token { val: current.clone(), line: token_start_line });
                    current.clear();
                }
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

pub fn clean_multiline(input: &str) -> String {
    input.lines()
        .map(|line| line.trim_start_matches('\t').trim_start_matches(' '))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

pub fn is_block_complete(input: &str) -> bool {
    let mut depth = 0;
    let mut in_quotes = false;

    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '"' && (i == 0 || chars[i - 1] != '\\') {
            in_quotes = !in_quotes;
        }

        if !in_quotes {
            let remaining = &input[i..];
            if remaining.starts_with("func") || remaining.starts_with("fn") || remaining.starts_with("if") || remaining.starts_with("repeat") || remaining.starts_with("def") || remaining.starts_with("function") {
                depth += 1;
            } else if remaining.starts_with("end") {
                depth -= 1;
            }
        }
        i += 1;
    }
    depth <= 0
}