---
name: moongrep-guide
description: build structural code search tools for MoonBit by matching parser AST JSON.
---

# Moongrep

## Overview

Use this guide to build MoonBit structural search by following this workflow:

1. write a template expression
2. use the installed `dump_expr` CLI to dump its AST JSON
3. turn that JSON into a MoonBit `match` pattern
4. create an `.mbtx` script with versioned imports and copy in the traversal helper
5. wire the matcher into the script and run it with `moon run`

## Workflow

### 0. Install `dump_expr` and prepare your `.mbtx` script

Install the helper binary once:

```bash
moon install https://github.com/moonbit-community/moongrep-guide.git
```

This installs `dump_expr` to `~/.moon/bin/dump_expr`.

In the directory where you want to implement structural search:

- create a script such as `<path/to/moongrep.mbtx>`
- put an `import { ... }` block at the top of the file
- write normal MoonBit code below that import block
- copy the helper code from `references/traverse_ast.mbt` into the script, then
  add your matcher and `main`

Example `.mbtx` import block:

```moonbit
import {
  "moonbitlang/core/env",
  "moonbitlang/parser@0.2.2/basic",
  "moonbitlang/parser@0.2.2/syntax",
  "moonbitlang/parser@0.2.2/lexer",
  "moonbitlang/parser@0.2.2/handrolled_parser",
  "moonbitlang/x@0.4.40/fs",
  "moonbitlang/x@0.4.40/sys",
}
```

If your script only contains the matcher helper and not a CLI, you can omit
`moonbitlang/x@0.4.40/fs` and `moonbitlang/x@0.4.40/sys`.

The script is then run directly with:

```bash
moon run <path/to/moongrep.mbtx>
```

### 1. Write a pattern template

Put the expression you want to match in a standalone file such as `<path/to/pattern.mbt>`.

Examples:

```mbt
_ARRAY.push(_VALUE)
```

```mbt
match _VALUE {
  Some(_ITEM) => _SOME_BODY
  None => _NONE_BODY
}
```

```mbt
for _COUNT = _N; _COUNT < _ARRAY.length(); _COUNT = _COUNT + 1 {
  _BODY
}
```

Use `references/traverse_ast_test.mbt` as the reference for useful placeholder
shapes and final matcher patterns.

### 2. Dump JSON from the template

first install `dump_expr`:

```bash
moon install https://github.com/moonbit-community/moongrep-guide.git
```

Run:

```bash
dump_expr <path/to/pattern.mbt>
```

Or save the output:

```bash
dump_expr <path/to/pattern.mbt> > <path/to/pattern.json>
```

The output is the parser AST JSON for that expression.

### 3. Convert JSON into a match pattern

Turn the dumped JSON into a MoonBit pattern used in a `match ast { ... }`
expression.

- keep the `kind` checks and child fields you care about
- replace literal placeholder names such as `_ARRAY` with pattern binds, usually
  `String(name)` under `LongIdent::Ident.value`
- use `..` to ignore fields and children you do not need
- use `Null` for JSON null values
- bind `loc` if you want to report match locations
- if the same placeholder appears multiple times, bind each position and enforce
  equality in code
- extract reusable subpatterns into helper predicates when that keeps the main
  match readable

Compare the raw `dump_expr` output with the hand-written JSON patterns in
`references/traverse_ast_test.mbt` to see the exact simplifications.

### 4. Implement the matcher inside your `.mbtx` script

After the import block, paste in the helper from `references/traverse_ast.mbt`.
That helper gives you two entry points:

- `traverse_top_impls(name~, source, callback)` parses a source string and walks
  each top-level impl
- `traverse_ast_json_repr(ast, callback)` walks an AST JSON tree you already
  have

The callback returns:

- `true` to keep traversing children
- `false` to stop descending into the current subtree

Inside the callback, `match` on the JSON object and push `loc` into your result
array when a pattern matches.

See `identify_c99style_for_loop`, `identify_match_option_some_none`, and
`identify_array_push_call` in `references/traverse_ast_test.mbt`.

### 5. Wire up the script so it scans `.mbt` files

If you want a runnable search tool, implement `main` in the same `.mbtx`
script:

- read a directory path from `@sys.get_cli_args()`
- use `@fs.read_dir` to list entries
- skip directories named `_build`, `.mooncakes`, or `target`
- keep only `.mbt` files
- read each file with `@fs.read_file_to_string`
- call your matcher on each file's source
- print the matched locations as JSON

This keeps the structural match logic in one file while still giving you a
simple command-line tool that you can run with `moon run <path/to/moongrep.mbtx>`.

## Notes

- `dump_expr` parses a single expression, so keep the pattern file limited to
  one expression snippet
- `references/traverse_ast_test.mbt` is the best reference for how raw dumped
  JSON becomes a practical matcher pattern
- `references/traverse_ast.mbt` depends on the versioned
  `moonbitlang/parser@0.2.2/...` imports shown above
- in an `.mbtx` script, keep the import block at the top and put the copied
  helper plus your matcher logic underneath
- use `moon run <path/to/moongrep.mbtx>` to verify that the copied helper and
  matcher compile and run correctly
