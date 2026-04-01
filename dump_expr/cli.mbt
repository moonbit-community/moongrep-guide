///|
fn[T] fatal(message : String, code? : Int = 1) -> T {
  println(message)
  @sys.exit(code)
  panic()
}

///|
fn main {
  let args = @sys.get_cli_args()
  let argv = match args {
    [_] => []
    [_, ..] => args[1:].to_array()
    _ => []
  }
  let source_or_path = parse_source_or_path(argv) catch {
    err => fatal(err.to_string(), code=2)
  }
  try {
    let source = if @fs.path_exists(source_or_path) &&
      @fs.is_file(source_or_path) {
      @fs.read_file_to_string(source_or_path)
    } else {
      source_or_path
    }
    let expr_json_repr = @greptools.dump_expr_json_repr(source).stringify(
      escape_slash=true,
      indent=2,
    )
    println(expr_json_repr)
  } catch {
    err => fatal(err.to_string())
  }
}
