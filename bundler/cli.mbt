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
  let (rules_root, output_path) = parse_bundle_args(argv) catch {
    err => fatal(err.to_string(), code=2)
  }
  try {
    @bundle.write_bundle(rules_root, output_path)
    println("generated \{output_path} from \{rules_root}")
  } catch {
    err => fatal(err.to_string())
  }
}
