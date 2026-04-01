///|
test "parse source or path accepts explicit input" {
  inspect(
    parse_source_or_path(["references/patterns/array_push_call.pattern.mbt"]),
    content="references/patterns/array_push_call.pattern.mbt",
  )
}

///|
test "parse source or path allows hyphen-prefixed expressions" {
  inspect(parse_source_or_path(["-1"]), content="-1")
}

///|
test "dump_expr command renders help for required input" {
  inspect(
    dump_expr_command().render_help(),
    content=(
      #|Usage: dump_expr <source-or-path>
      #|
      #|Arguments:
      #|  source-or-path  Expression source or file path
      #|
      #|Options:
      #|  -h, --help  Show help information.
      #|
    ),
  )
}

///|
test "parse source or path rejects unexpected extra arguments" {
  try parse_source_or_path(["references", "extra"]) catch {
    err =>
      inspect(
        err.to_string(),
        content=(
          #|error: unexpected value 'extra' for '<source-or-path>' found; no more were expected
          #|
          #|Usage: dump_expr <source-or-path>
          #|
          #|Arguments:
          #|  source-or-path  Expression source or file path
          #|
          #|Options:
          #|  -h, --help  Show help information.
          #|
        ),
      )
  } noraise {
    _ => panic()
  }
}
