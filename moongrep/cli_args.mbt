///|
let moongrep_command_name = "moongrep"

///|
fn moongrep_command() -> @argparse.Command {
  @argparse.Command(moongrep_command_name, positionals=[
    @argparse.PositionArg("scan-root", about="Root directory to scan", default_values=[
      ".",
    ]),
  ])
}

///|
fn parse_scan_root(argv : Array[String]) -> String raise {
  let matches = moongrep_command().parse(argv~)
  match matches.values.get("scan-root") {
    Some(values) => if values is [scan_root, ..] { scan_root } else { "." }
    None => "."
  }
}
