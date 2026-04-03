///|
pub fn generate_bundle_source(rules_root : String) -> String raise {
  let rules = @load.load_rules(rules_root)
  @emit.emit_bundle_source(rules)
}

///|
pub fn write_bundle(rules_root : String, output_path : String) -> Unit raise {
  let source = generate_bundle_source(rules_root)
  @fs.write_string_to_file(output_path, source)
}
