# .xeo

**.xeo** is a standalone, reversible, bash/lua-like scripting lang 
for **xeon** built on rust, featuring 28 core commands:

## core commands

### output & input
- `print <args>`: writes all args on terminal.
- `ask $var <prompt>`: asks the user a question, and returns the input as a variable.

### variables & math
- `calc <expr> as $var`: calculates math expression and returns it as a variable.
- `string <expr> as $var`: concatenates strings or returns string as a variable.
- `find $haystack <needle> $bool`: looks for string in specified variable, and returns a boolean as a variable.
- `fetch <url> $var`: sets a variable to url content.
- `args $arg1 $arg2 $arg3 ...`: grabs any number of arguments from initial command execution

### flow control
- `dir <path>`: changes execution path.
- `go <line>`: goes to line number in code.
- `if <bool>`: executes the commands under it if the condition is met.
- `repeat <count> as <var>`: repeats the commands under it a specific number of times, while providing an iterator.
- `exit`: terminates the script execution.

### file system (reversible)
- `make <file>`: creates a file and logs it for potential reversal.
- `mkdir <dir>`: creates a directory and logs it for potential reversal.
- `move <src> <dest>`: moves a file or directory.
- `copy <src> <dest>`: copys a file or directory.
- `delete <file>`: removes a file (logs for restoration if reversible).
- `append <file> <text>`: appends text to a file.
- `replace <file> <text>`: replaces file content.
- `link <dest> <path>`: creates a symbolic link.
- `chmod <file>`: makes file executable.
- `wget <url> <dest>`: download (with built-in rename semantics).
- `ls <path> $var`: returns files in directory as a string variable.

### modularity & system
- `use <file>`: executes another .xeo file in current scope.
- `ext <plugin>`: runs a global extension from ~/.xeon/bin.
- `func <name>`: defines a reusable block of code.
- `end`: ends an if, repeat, or function statement.
- `run <name>`: executes a previously defined function.

---

## features

### reversibility (undo engine)
xeo is built with a "safety-first" mindset. every time you use a command like `make` or `mkdir`, the engine pushes the action onto a stack. if the script fails or is run in reverse mode, xeo reads the `revlog` to delete created files and undo changes in lifo (last-in, first-out) order.

### global extensions
instead of bloating the core binary, xeo uses the `~/.xeon` directory to store plugins. using the `ext` command, you can trigger specialized rust binaries or shell scripts that reside in your home folder, making the language infinitely expandable, while keeping **.xeo itself around 1MB.**

### standalone simplicity
the interpreter is a single rust binary with zero dependencies. it handles variable interpolation, basic math, and file i/o out of the box.

### modularity
with the `use` and `func` commands, scripts can be broken down into reusable modules. variables can be shared across files, allowing you to build complex systems from simple, readable .xeo files.

---

## quick start
1. run `curl -fsSL https://github.com/arozoid/xeo/releases/latest/download/install.sh | bash` in your terminal.
2. run xeo in your terminal. if it works, congrats. if it doesn't, and you're on macos, please run these two commands in your terminal:
```
# Remove the download restriction
xattr -d com.apple.quarantine ./xeo-macos

# Locally sign the binary so the kernel allows it to run
codesign -s - ./xeo-macos --force
```

> **note:** .xeo is installed locally (~/.xeon/ directory). if you want to use .xeo on another user, please run the install script again.