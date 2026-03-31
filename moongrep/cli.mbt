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
  let scan_root = parse_scan_root(argv) catch {
    err => fatal(err.to_string(), code=2)
  }
  try {
    let scan_result = collect_directory_hits(scan_root)
    for skipped in scan_result.skipped_files {
      println(render_skipped_file_message(skipped))
    }
    if !scan_result.skipped_files.is_empty() && !scan_result.hits.is_empty() {
      println("")
    }
    let hits = scan_result.hits
    if hits.is_empty() {
      println("no match hits")
    } else {
      for index in 0..<hits.length() {
        if index != 0 {
          println("")
        }
        println(hits[index])
      }
    }
  } catch {
    Failure::Failure(err) => fatal(err)
    err => fatal(err.to_string())
  }
}
