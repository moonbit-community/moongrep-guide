///|
let dump_expr_command_name = "dump_expr"

///|
fn dump_expr_command() -> @argparse.Command {
  @argparse.Command(dump_expr_command_name, positionals=[
    @argparse.PositionArg(
      "source-or-path",
      about="Expression source or file path",
      num_args=@argparse.ValueRange::single(),
      allow_hyphen_values=true,
    ),
  ])
}

///|
fn parse_source_or_path(argv : Array[String]) -> String raise {
  let matches = dump_expr_command().parse(argv~)
  match matches.values.get("source-or-path") {
    Some(values) =>
      if values is [source_or_path, ..] {
        source_or_path
      } else {
        fail("missing required argument: source-or-path")
      }
    None => fail("missing required argument: source-or-path")
  }
}
