///|
fn main {
  let scan_root = match @sys.get_cli_args() {
    [_] => "."
    [_, scan_root] => scan_root
    otherwise => {
      println("invalid cli arguments: \{otherwise}")
      println("usage: moon run moongrep [scan-root]")
      panic()
    }
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
    Failure::Failure(err) => {
      println(err)
      panic()
    }
    err => {
      println(err)
      panic()
    }
  }
}
