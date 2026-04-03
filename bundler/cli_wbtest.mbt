///|
test "parse bundle args defaults both positional values" {
  inspect(
    parse_bundle_args([]),
    content="(\"rules\", \"rules/bundled_rules.mbt\")",
  )
}

///|
test "parse bundle args accepts explicit rules root only" {
  inspect(
    parse_bundle_args(["references/rules"]),
    content="(\"references/rules\", \"rules/bundled_rules.mbt\")",
  )
}

///|
test "parse bundle args accepts explicit rules root and output path" {
  inspect(
    parse_bundle_args(["references/rules", "tmp/output.mbt"]),
    content="(\"references/rules\", \"tmp/output.mbt\")",
  )
}

///|
test "bundler command renders help for optional arguments" {
  inspect(
    bundler_command().render_help(),
    content=(
      #|Usage: bundler [rules-root] [output-path]
      #|
      #|Arguments:
      #|  rules-root   Directory containing YAML rules [default: rules]
      #|  output-path  Path to write generated bundled rules [default: rules/bundled_rules.mbt]
      #|
      #|Options:
      #|  -h, --help  Show help information.
      #|
    ),
  )
}

///|
test "parse bundle args rejects unexpected extra arguments" {
  try parse_bundle_args(["rules", "rules/bundled_rules.mbt", "extra"]) catch {
    err =>
      inspect(
        err.to_string(),
        content=(
          #|error: unexpected value 'extra' for '<output-path>' found; no more were expected
          #|
          #|Usage: bundler [rules-root] [output-path]
          #|
          #|Arguments:
          #|  rules-root   Directory containing YAML rules [default: rules]
          #|  output-path  Path to write generated bundled rules [default: rules/bundled_rules.mbt]
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
