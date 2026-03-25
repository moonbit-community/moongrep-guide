///|
fn apply_bundled_rules(
  file : String,
  ast : Json,
  hits : Array[MatchHit],
) -> Bool {
  let mut keep_traversing = true
  for _, rule_matcher in moongrep_rules_table.iter2() {
    keep_traversing = rule_matcher(file, ast, hits) && keep_traversing
  }
  keep_traversing
}
