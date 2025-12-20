# .xeo

**.xeo** is a standalone, reversible, bash/lua-like scripting lang 
for **xeon** built on rust, featuring 24 core commands:

- `print <args>` (writes all args on terminal)
- `calc <expr> as $var` (calculates math expression and returns it as a variable)
- `string <expr> as $var` (concatenates strings or returns string as a variable)
- `ask $var <prompt>` (asks the user a question, and returns the input as a variable)
- `go <line>` (goes to line number in code)
- `use <file>` (executes another .xeo file in current scope)
- `make <file>` (creates a file and logs it for potential reversal)
- `ext <plugin>` (runs a global extension from ~/.xeon/bin)

## features

### reversibility (undo engine)
xeo is built with a "safety-first" mindset. every time you use a command like `make` or `mkdir`, the engine pushes the action onto a stack. if the script fails or is run in reverse mode, xeo reads the `revlog` to delete created files and undo changes in lifo (last-in, first-out) order.

### global extensions
instead of bloating the core binary, xeo uses the `~/.xeon` directory to store plugins. using the `ext` command, you can trigger specialized rust binaries or shell scripts that reside in your home folder, making the language infinitely expandable.

### standalone simplicity
the interpreter is a single rust binary with zero dependencies. it handles variable interpolation, basic math, and file i/o out of the box.

### modularity
with the `use` and `func` commands, scripts can be broken down into reusable modules. variables can be shared across files, allowing you to build complex systems from simple, readable .xeo files.



## quick start
1. run `curl -fsSL https://github.com/arozoid/xeo/releases/latest/download/install.sh | bash` in your terminal
2. that's it! enjoy using .xeo! NOTE: .xeo is installed locally (~/.xeon/ directory). if you want to use .xeo on another user, please run the install script again.