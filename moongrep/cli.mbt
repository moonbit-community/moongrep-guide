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
    let hits = collect_directory_hits(scan_root)
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
