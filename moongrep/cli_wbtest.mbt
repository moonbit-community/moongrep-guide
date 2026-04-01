///|
test "parse scan root defaults to current directory" {
  inspect(parse_scan_root([]), content=".")
}

///|
test "parse scan root accepts explicit path" {
  inspect(parse_scan_root(["references"]), content="references")
}

///|
test "moongrep command renders help for optional scan root" {
  inspect(
    moongrep_command().render_help(),
    content=(
      #|Usage: moongrep [scan-root]
      #|
      #|Arguments:
      #|  scan-root  Root directory to scan [default: .]
      #|
      #|Options:
      #|  -h, --help  Show help information.
      #|
    ),
  )
}

///|
test "parse scan root rejects unexpected extra arguments" {
  try parse_scan_root(["references", "extra"]) catch {
    err =>
      inspect(
        err.to_string(),
        content=(
          #|error: unexpected value 'extra' for '<scan-root>' found; no more were expected
          #|
          #|Usage: moongrep [scan-root]
          #|
          #|Arguments:
          #|  scan-root  Root directory to scan [default: .]
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
