///|
fn apply_bundled_rules(
  file : String,
  ast : Json,
  hits : Array[@greptools.MatchHit],
) -> Bool raise {
  let mut keep_traversing = true
  for _, rule_matcher in @rules.moongrep_rules_table.iter2() {
    keep_traversing = rule_matcher(file, ast, hits) && keep_traversing
  }
  keep_traversing
}

///|
fn taint_pattern_index(rule : @rules.BundledTaintRule, sink_id : String) -> Int {
  for index in 0..<rule.sink_ids.length() {
    if rule.sink_ids[index] == sink_id {
      return index
    }
  }
  0
}

///|
fn push_taint_analysis_hits(
  file : String,
  rule : @rules.BundledTaintRule,
  result : @taint.AnalysisResult,
  hits : Array[@greptools.MatchHit],
) -> Unit {
  for finding in result.findings {
    hits.push(@greptools.MatchHit::{
      file,
      rule_id: rule.rule_id,
      package_name: rule.package_name,
      description: rule.description,
      pattern_index: taint_pattern_index(rule, finding.sink_id),
      loc: finding.sink_loc,
    })
  }
}

///|
fn apply_bundled_taint_rules(
  file : String,
  ast : Json,
  hits : Array[@greptools.MatchHit],
) -> Unit raise {
  match ast {
    { "kind": "Impl::TopFuncDef", .. } | { "kind": "Impl::TopImpl", .. } =>
      for rule in @rules.moongrep_taint_rules {
        let result = @taint.analyze_function_like_json(ast, rule.spec)
        push_taint_analysis_hits(file, rule, result, hits)
      }
    _ => ()
  }
}
