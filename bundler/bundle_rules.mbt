///|
priv suberror RuleBundleError {
  InvalidRule(path~ : String, info~ : String)
} derive(Show)

///|
fn generate_bundle_source(
  rules_root? : String = default_rules_root,
) -> String raise {
  let rules = load_rules(rules_root)
  emit_bundle_source(rules)
}

///|
fn write_bundle(
  rules_root? : String = default_rules_root,
  output_path? : String = default_output_path,
) -> Unit raise {
  let source = generate_bundle_source(rules_root~)
  @fs.write_string_to_file(output_path, source)
}
