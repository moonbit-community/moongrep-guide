///|
let default_rules_root = "rules"

///|
let default_output_path = "rules/bundled_rules.mbt"

///|
let bundler_command_name = "bundler"

///|
fn bundler_command() -> @argparse.Command {
  @argparse.Command(bundler_command_name, positionals=[
    @argparse.PositionArg(
      "rules-root",
      about="Directory containing YAML rules",
      default_values=[default_rules_root],
    ),
    @argparse.PositionArg(
      "output-path",
      about="Path to write generated bundled rules",
      default_values=[default_output_path],
    ),
  ])
}

///|
fn parse_bundle_args(argv : Array[String]) -> (String, String) raise {
  let matches = bundler_command().parse(argv~)
  let rules_root = match matches.values.get("rules-root") {
    Some(values) =>
      if values is [value, ..] {
        value
      } else {
        default_rules_root
      }
    None => default_rules_root
  }
  let output_path = match matches.values.get("output-path") {
    Some(values) =>
      if values is [value, ..] {
        value
      } else {
        default_output_path
      }
    None => default_output_path
  }
  (rules_root, output_path)
}
