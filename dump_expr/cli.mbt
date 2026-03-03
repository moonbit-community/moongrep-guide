///|
fn main {
  let filename = match @sys.get_cli_args() {
    [_, filename] => filename
    otherwise => {
      println("invalid cli arguments: \{otherwise}")
      panic()
    }
  }
  try {
    let source = @fs.read_file_to_string(filename)
    let expr_json_repr = dump_expr_json_repr(source).stringify(
      escape_slash=true,
      indent=2,
    )
    println(expr_json_repr)
  } catch {
    err => {
      println(err)
      panic()
    }
  }
}
