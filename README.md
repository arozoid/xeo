# .xeo

**.xeo** is a lightweight bash/lua-like scripting language for **xeon** built in rust, keeping the core language to just 20 commands while staying fast, standalone, and easy to extend.

## core commands

### output & input

- `print <args>` writes values to the terminal with `$var` interpolation inside strings.
- `ask $var <prompt>` asks the user a question and stores the response in a variable.

### variables & math

- `set $var <expr>` sets a variable, evaluating numeric expressions like `1 + 2 * 3` into `7` while concatenating strings normally. `let` is an alias.
- `find $haystack <needle> $bool` checks whether one string exists inside another and stores the result as a boolean.
- `get <expr> as $var` evaluates an expression into a variable name before retrieving that variable's value.

### flow control

- `if <expr>` runs a block when its condition is true.
- `else` runs when the preceding `if` was false.
- `repeat <count> as $var` repeats a block a fixed number of times while providing an iterator that starts at `0`.
- `break` exits the current loop.
- `continue` skips to the next iteration.
- `return` exits the current function early.
- `wait <ms>` pauses execution for a number of milliseconds. `sleep` is an alias.
- `exit` terminates the script immediately.

### modularity & system

- `use <module>` loads a library from the current directory or `~/.xeon/lib`, only importing each module once per session. `import` is an alias.
- `func <name> $arg1 $arg2 ...` defines a reusable function.
- `end` closes an `if`, `else`, `repeat`, or `func` block.
- `run <name> <arg1> ...` calls a function. `call` is an alias.
- `coreadd <name>` registers a function so it can be called like a built-in command.
- `ext <cmd> <args...>` runs a global extension from `~/.xeon/bin`.
- `extc <cmd> <args...>` runs an extension and captures its output into `$res`.

---

## expressions

variables interpolate into strings with `$name`, while arithmetic, comparisons, and boolean logic all work together naturally inside expressions.

| operators | meaning |
|---|---|
| `+ - * / % ^` | arithmetic |
| `()` | grouping |
| `== != < > <= >=` | comparisons |
| `&& \|\|` | boolean logic |
| `true false` | boolean literals |

examples:

```xeo
set $x 1 + 2 * 3
set $s "hello" + " world"

if $x > 5 && $ok
```

---

## comments

`#` and `--` create single-line comments, while quoted multi-line strings preserve their original formatting.

---

## features

### double-pipe protocol (`xeo --pipe`)

`xeo -p` starts a persistent stdin/stdout session that lets external programs talk to xeo without restarting the interpreter every time, keeping variables, functions, and imported modules alive between requests so it behaves more like an embedded scripting engine than a disposable process.

every request produces exactly one response frame ending with:

```text
__XEO_DONE__
```

program output appears before the sentinel, while runtime errors are returned as `ERR:` lines.

example:

```text
send:  set $a 5

recv:  __XEO_DONE__

send:  print "a=" $a

recv:  a= 5
       __XEO_DONE__

send:  if $a > 2
         print "big"
       end

recv:  big
       __XEO_DONE__
```

### library loading (`use`)

modules live as plain `.xeo` files in the current directory or `~/.xeon/lib`, loading only once per session so importing the same module twice never duplicates it.

```xeo
use printc
printc "{green}hi{clear}"
```

### global extensions

instead of bloating the interpreter with niche features, xeo delegates specialized commands to standalone binaries inside `~/.xeon/bin`, making new functionality as simple as dropping in another executable while keeping the core binary around **1 mb**.

### standalone by design

xeo runs as a single rust binary with zero runtime dependencies, handling variables, interpolation, expressions, functions, modules, and structured output without dragging in a heavyweight runtime.

---

## quick start

```sh
# build from source
cargo build --release
cp target/release/xeo ~/.xeon/bin/xeo

# run a script
xeo script.xeo

# start a persistent pipe session
xeo -p
```
