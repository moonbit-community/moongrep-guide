///|
fn main {
  let (rules_root, output_path) = match @sys.get_cli_args() {
    [_] => (default_rules_root, default_output_path)
    [_, rules_root] => (rules_root, default_output_path)
    [_, rules_root, output_path] => (rules_root, output_path)
    otherwise => {
      println("invalid cli arguments: \{otherwise}")
      panic()
    }
  }
  try {
    write_bundle(rules_root~, output_path~)
    println("generated \{output_path} from \{rules_root}")
  } catch {
    err => {
      println(err)
      panic()
    }
  }
}
