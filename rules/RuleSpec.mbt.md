# Rule Specification

This document is the authoritative specification for YAML rules in the
`rules` package.

If you are writing your first rule, start with [README.mbt.md](README.mbt.md).

## Scope and Status

This document specifies the current rule file format, bundler validation, and
generated matcher semantics implemented by the `rules` package.

Unless stated otherwise, the keywords "must", "must not", "may", and
"currently" describe the behavior of the current implementation.

## Rule File Model

- The bundler recursively scans the rules root for files ending in `.yaml` or
  `.yml`.
- If no YAML rule files are found, bundling is rejected.
- Each rule file must contain exactly one YAML document.
- The top-level YAML document must be a mapping.
- Each rule file defines exactly one rule.

Rule ids are derived from the rule file path relative to the rules root:

- the relative path is computed against `<rules-root>/`
- the trailing `.yaml` or `.yml` suffix is removed
- the remaining relative path becomes the rule id

Example:

- `rules/rabbita/nav-load.yaml` -> `rabbita/nav-load`

## YAML Schema

### Top-Level Keys

Only these keys are accepted:

- `package` (required): YAML string
- `description` (required): YAML string
- `patterns` (required): non-empty YAML array

Any other top-level key is rejected.

No semantic validation is performed on `package` or `description` beyond
requiring them to be YAML strings. `description` is stored verbatim in the
generated `MatchHit`; if YAML block-scalar syntax preserves a trailing newline,
that newline is preserved in the stored value.

### Pattern Objects

Each entry in `patterns` must be a mapping.

Only these keys are accepted:

- `shape` (required): YAML string
- `metavars` (optional): YAML mapping
- `guard` (optional): YAML string

Any other key inside a pattern object is rejected.

### `metavars`

If `metavars` is present, it must be a mapping. Only these keys are accepted:

- `subtree` (optional): array of strings
- `identifier` (optional): array of strings

If either bucket is omitted, it defaults to the empty array.

Each bucket:

- must be an array if present
- may contain only strings
- must not contain duplicate names

Across buckets:

- a metavar name must not appear in both `subtree` and `identifier`

## `shape`

`shape` must be a single MoonBit expression snippet accepted by the expression
parser used by `@greptools.dump_expr_json_repr(...)`.

Normatively:

- `shape` is parsed with the expression parser, not the full-file parser
- `shape` must therefore be valid as one expression-sized snippet
- `shape` is not an arbitrary module fragment or entire source file

The bundler parses `shape` into AST JSON and then emits a MoonBit `match`
pattern from that JSON. The rule author writes surface MoonBit syntax; the
generated matcher operates on AST JSON.

## Matching Model

The runtime matcher is applied to traversed AST subtrees, not to entire files as
single units.

Current traversal model:

- the scanner parses a source file into top-level impls
- each top-level impl is traversed recursively
- each visited subtree is passed to every generated rule matcher

Pattern semantics:

- each entry in `patterns` becomes one matcher arm
- the arms are OR-ed together
- any matching arm may emit a `MatchHit`
- the hit records the zero-based `pattern_index` of the arm that matched
- all arms in the same rule share the same `rule_id`, `package`, and
  `description`

The location stored in `MatchHit.loc` is the `loc` field of the matched root AST
subtree for that pattern arm.

## Metavariable Recognition

Identifiers inside `shape` are not metavariables by default. A name only becomes
a metavariable if:

- it is declared under `metavars`
- it appears in a supported metavariable-capable AST position

Current supported AST positions are:

- `Expr::Ident`
- `Var`
- `Binder`
- `Pattern::Var`
- `Label`

Names made only of two or more underscores, such as `__`, `___`, and `____`,
are special ignore placeholders:

- it must not be declared under `metavars`
- in the supported positions above, it matches anything in that one position
- it does not bind a value for equality checks or guards
- repeated occurrences are independent wildcards
- in non-supported positions, it is treated literally as that identifier or
  other source-level text
- this rule is separate from MoonBit's own special handling of `_`

Current non-supported examples include:

- constructor names
- arbitrary string-valued fields
- any position that is not one of the supported AST node kinds above

If a name is declared under `metavars` but only appears in unsupported
positions, bundling is rejected with an "unused metavar" error because no
binding is generated for that name.

Undeclared names are matched literally according to the AST JSON produced from
`shape`.

## `subtree` Semantics

A `subtree` metavar binds the matched AST subtree as raw `Json`.

Consequences:

- the guard receives that metavar as `Json`
- repeating the same `subtree` metavar in one pattern requires structural AST
  equality across all occurrences after removing `loc` fields recursively
- the equality check is performed in generated matcher code before the guard

Example:

```yaml
patterns:
  - shape: _expr == _expr
    metavars:
      subtree: [_expr]
```

This can match repeated non-trivial subtrees such as `items[i] == items[i]`
because the whole expression subtree is compared structurally rather than by
source location.

`subtree` is usually the wrong choice when the same source-level name appears
once as a binder and later as an identifier expression or label, because those
are different AST node kinds and therefore not structurally equal.

## `identifier` Semantics

An `identifier` metavar binds by normalized identifier or label name rather
than by raw AST equality.

Current normalization succeeds only for:

- simple variable targets represented as `Var` with `LongIdent::Ident`
- `Binder`
- simple identifier expressions represented as `Expr::Ident`
- `Pattern::Var`
- `Label`

If normalization succeeds:

- the guard receives the metavar as `String`
- repeating the same `identifier` metavar requires all normalized strings to be
  equal

If normalization fails for any occurrence:

- the pattern does not emit a hit
- no exception is raised

This is the intended tool for cases where the same logical name appears across
different AST node kinds, such as loop-variable binders and later identifier
uses, or repeated field and method labels in expressions such as
`record.field = record.field + value` and `receiver.method()`.

## Guard Semantics

If present, `guard` must be a non-blank YAML string after trimming leading and
trailing whitespace. A blank guard is rejected.

The bundler validates `guard` syntax by wrapping it as a MoonBit expression
inside a helper function and parsing the result. A syntactically invalid guard
is rejected during bundling.

Guard parameter types are:

- `subtree` metavars -> `Json`
- `identifier` metavars -> `String`

Guard evaluation order for a matching pattern is:

1. bind all declared metavars that occur in supported positions
2. for `identifier`, normalize each occurrence to `String?`
3. if any `identifier` normalization fails, do not emit a hit
4. if a repeated metavar appears multiple times, check generated equality
5. if a guard is present, evaluate it
6. if the guard yields `true`, push a hit

Additional notes:

- duplicate-equality checks run before the guard
- guards that parse successfully but do not type-check as generated code are
  caught later when compiling the generated bundle
- guard source is compiled inside the `rules` package, so normal package-scope
  name resolution applies

## Reserved Names

The following names are reserved and must not be declared as metavars:

- any name consisting only of two or more underscores
- `file`
- `hits`
- `loc`
- any name beginning with `__moongrep_`

These names are reserved because generated matcher code uses them for function
parameters, local bindings, synthesized helper names, and built-in placeholder
semantics.

## Error Conditions

Bundling is rejected in the following cases:

- the rules root contains no YAML rule files
- a rule file contains zero YAML documents or more than one YAML document
- the top-level YAML document is not a mapping
- a required key is missing
- `package`, `description`, or `shape` is not a YAML string
- `patterns` is not an array or is empty
- a `patterns` entry is not a mapping
- an unsupported key appears at top level, inside a pattern, or inside
  `metavars`
- `metavars` is present but not a mapping
- a metavar bucket is present but not an array
- a metavar bucket contains a non-string entry
- a metavar name is duplicated within one bucket
- a metavar name appears in both `subtree` and `identifier`
- a metavar uses a reserved name
- a declared metavar is never bound in a supported position
- `guard` is present but not a string
- `guard` is blank after trimming
- `guard` is not syntactically valid MoonBit expression syntax
- two rule ids would generate the same matcher function name after replacing
  `/` and `-` with `_`

## Runtime Interface

The generated bundle exports:

```moonbit nocheck
pub let moongrep_rules_table : Map[String, (String, Json, Array[MatchHit]) -> Bool raise]
```

For each rule matcher function:

- argument 1: `file`, the current file name or path string reported in hits
- argument 2: `ast`, the current traversed AST subtree as `Json`
- argument 3: `hits`, the mutable hit array to append to
- return value: whether traversal should continue into child subtrees

Current implementation note:

- generated rule matchers always return `true`
- matching a rule does not currently prune traversal

Each emitted hit contains:

- `file`
- `rule_id`
- `package` from YAML `package`
- `description` from YAML `description`
- zero-based `pattern_index`
- `loc` of the matched root subtree

## Normative Examples

### Repeated subtree equality

```yaml
package: moonbitlang/core
description: |
  Repeated subtree equality.
patterns:
  - shape: _expr == _expr
    metavars:
      subtree: [_expr]
```

Semantics:

- `_expr` binds as `Json`
- both occurrences must be structurally equal AST JSON after removing `loc`
  fields recursively
- `x == x` may match
- `items[i] == items[i]` may match

### Binder/use-name comparison

```yaml
package: moonbitlang/core
description: |
  Counter-style `for` loop.
patterns:
  - shape: |
      for counter = _start; counter < upper_limit; counter = counter + 1 {
        body
      }
    metavars:
      subtree: [_start, upper_limit, body]
      identifier: [counter]
```

Semantics:

- `_start`, `upper_limit`, and `body` bind as `Json`
- each `counter` occurrence must normalize to a simple identifier name
- all normalized `counter` strings must be equal

### Multi-pattern rule

```yaml
package: moonbitlang/async/http
description: |
  These HTTP parser entrypoints accept messages where `Content-Length` and
  `Transfer-Encoding` may coexist.
patterns:
  - shape: |
      _conn.read_request()
    metavars:
      subtree: [_conn]
  - shape: |
      _client.end_request()
    metavars:
      subtree: [_client]
```

Semantics:

- the first and second patterns are separate OR arms
- either arm may emit a hit
- both arms use the same `rule_id`, `package`, and `description`
- the hit distinguishes them through `pattern_index`
