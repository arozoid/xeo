# .xeo

**.xeo** is a standalone, bash/lua-like scripting lang
for **xeon** built on rust, featuring 20 core commands:

## core commands

### 2 output & input commands
- `print <args>`: writes all args on terminal, with `$var` interpolation in strings.
- `ask $var <prompt>`: asks the user a question, and returns the input as a variable.

### 3 variables & math commands
- `set $var <expr>`: sets a variable. if the expression is numeric, it's evaluated with the math engine (`1 + 2 * 3` → `7`); otherwise it's concatenated as a string. aliased as `let`.
- `find $haystack <needle> $bool`: looks for a string inside a variable, and returns a boolean as a variable.
- `get <expr> as $var`: evaluates the expression to form a variable name, then retrieves that variable's value into another variable.

### 8 flow control commands
- `if <expr>`: executes the commands under it if the condition is met. expressions support `==`, `!=`, `<`, `>`, `<=`, `>=`, `&&`, `||`, and `true`/`false`.
- `else`: runs when the preceding `if` was false (linked to the same `end`).
- `repeat <count> as $var`: repeats the commands under it a specific number of times, providing an iterator that starts at 0.
- `break`: stops the current repeat loop.
- `continue`: skips to the next iteration of the current repeat loop.
- `return`: exits the current function early.
- `wait <ms>`: pauses the code for the specified milliseconds. (1 second = 1000ms) aliased as `sleep`.
- `exit`: terminates the script execution.

### 7 modularity & system commands
- `use <module>`: loads a library from the current directory or `~/.xeon/lib`. loading is idempotent per session. aliased as `import`.
- `func <name> $arg1 $arg2 ... $argN`: defines a reusable block of code with optional arguments.
- `end`: closes an `if`, `else`, `repeat`, or `func` block.
- `run <name> <arg1> ... <argN>`: calls a previously defined function. aliased as `call`.
- `coreadd <name>`: registers a function name so it can be called as a bare command (e.g. `coreadd yess` then `yess "brozo"`).
- `ext <cmd> <arg1> ... <argN>`: runs a global extension binary from `~/.xeon/bin`.
- `extc <cmd> <arg1> ... <argN>`: runs a global extension and captures its stdout into the `$res` variable.

---

## expressions

variables are interpolated inside any string with `$name`. math, comparison, and
logic can be combined in `if` and `set` expressions:

| operators | meaning |
|---|---|
| `+ - * / % ^` | arithmetic (with `()` grouping, e.g. `(2 + 3) * 4` → `20`) |
| `== != < > <= >=` | comparison |
| `&& \|\|` | logic |
| `true false` | boolean literals |

examples:

```
set $x 1 + 2 * 3        # $x = 7
set $s "hello" + " world"   # $s = hello world (string concat)
if $x > 5 && $ok         # combined condition
```

## comments

`#` and `--` start a comment that runs to the end of the line. multi-line strings
keep their newlines when quoted.

---

## features

### double-pipe protocol (`xeo --pipe`)

`xeo -p` starts a persistent, framed request/response session over stdin/stdout so
external programs can drive xeo like an embedded library — no import needed.

- Send one or more xeo statements as a **request**, terminated by a blank line (or EOF).
- xeo keeps its variables, functions, and loaded modules alive between requests.
- Each request produces exactly one framed **response**, terminated by:
  ```
  __XEO_DONE__
  ```
- Program output (from `print`, `ext`, ...) appears before the sentinel; runtime
  errors appear as `ERR: <message>` lines, also before the sentinel. raw ANSI
  error output still goes to stderr.

example (from a host program):
```
send:  set $a 5\n\n
recv:  __XEO_DONE__

send:  print "a=" $a\n\n
recv:  a= 5
       __XEO_DONE__

send:  if $a > 2\n  print "big"\nend\n\n
recv:  big
       __XEO_DONE__
```

### library loading (`use`)
modules live in the current directory or `~/.xeon/lib` as plain `.xeo` files.
`use printc` loads `printc.xeo` once per session and appends it inline so the
functions it defines stay callable:

```xeo
use printc
printc "{green}hi{clear}"
```

### global extensions
instead of bloating the core binary, xeo runs specialized binaries from
`~/.xeon/bin` via `ext`. adding a new language command is just dropping a binary
in that folder. **.xeo itself stays around 1MB.**

### standalone simplicity
the interpreter is a single rust binary with zero dependencies, handling
variable interpolation, math, logic, and JSON-free structured output out of the
box.

---

## quick start

```sh
# build from source
cargo build --release
cp target/release/xeo ~/.xeon/bin/xeo

# run a script
xeo script.xeo

# start an interactive / embedded pipe session
xeo -p
```
