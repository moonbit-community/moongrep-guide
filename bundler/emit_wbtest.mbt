///|
test "emit bundle source builds package-local matcher file" {
  let source = emit_bundle_source([
    {
      rule_id: "example/test",
      package_name: "moonbit-community/example",
      description: "example rule",
      patterns: [
        {
          shape: "node.set_inner_html(html)",
          metavars: ["node", "html"],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_false(source.has_prefix("import {\n"))
  assert_true(source.contains("fn example_test"))
  assert_false(source.contains("fn apply_bundled_rules"))
  assert_true(source.contains("let moongrep_rules_table"))
  assert_true(source.contains("\"example/test\": example_test"))
  assert_false(source.contains("impl Show for MatchHit"))
  assert_false(source.contains("fn collect_source_files"))
  assert_false(source.contains("usage: moon run moongrep.mbtx [scan-root]"))
}

///|
test "emit bundle source generates one matcher function per rule" {
  let source = emit_matcher_source([
    {
      rule_id: "example/first",
      package_name: "moonbit-community/example",
      description: "first rule",
      patterns: [
        {
          shape: "node.set_inner_html(html)",
          metavars: ["node", "html"],
          pattern_guard: None,
        },
        {
          shape: "node.set_outer_html(html)",
          metavars: ["node", "html"],
          pattern_guard: None,
        },
      ],
    },
    {
      rule_id: "example/second",
      package_name: "moonbit-community/example",
      description: "second rule",
      patterns: [
        {
          shape: "value.apply(args)",
          metavars: ["value", "args"],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_true(source.contains("// bundled rule: example/first"))
  assert_true(source.contains("// bundled rule: example/second"))
  assert_true(source.contains("fn example_first"))
  assert_true(source.contains("fn example_second"))
  assert_false(source.contains("fn apply_bundled_rules"))
  assert_true(source.contains("\"example/first\": example_first"))
  assert_true(source.contains("\"example/second\": example_second"))
}

///|
test "emit matcher source exposes first metavar bindings without guard" {
  let source = emit_matcher_source([
    {
      rule_id: "example/test",
      package_name: "moonbit-community/example",
      description: "example rule",
      patterns: [
        {
          shape: "node.set_inner_html(html)",
          metavars: ["node", "html"],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_true(source.contains("\"self\": node"))
  assert_true(source.contains("\"value\": html"))
  assert_true(source.contains("\"node\": node"))
  assert_true(source.contains("\"html\": html"))
  assert_false(source.contains("meta_node_1"))
  assert_false(source.contains("meta_html_1"))
}

///|
test "reject conflicting rule matcher function names" {
  let result = try? emit_rule_matcher_function_names([
    {
      rule_id: "example/a-b",
      package_name: "moonbit-community/example",
      description: "first rule",
      patterns: [],
    },
    {
      rule_id: "example/a_b",
      package_name: "moonbit-community/example",
      description: "second rule",
      patterns: [],
    },
  ])
  match result {
    Err(InvalidRule(path~, info~)) => {
      inspect(path, content="example/a_b")
      inspect(
        info,
        content="rule matcher function name conflict: example/a-b and example/a_b both map to example_a_b",
      )
    }
    _ => fail("expected rule matcher function name conflict")
  }
}

///|
test "emit matcher source checks duplicate equality before guard" {
  let source = emit_matcher_source([
    {
      rule_id: "example/guarded",
      package_name: "moonbit-community/example",
      description: "guarded rule",
      patterns: [
        {
          shape: "pair(left, left)",
          metavars: ["pair", "left"],
          pattern_guard: Some("left != pair"),
        },
      ],
    },
  ])
  assert_false(source.contains("} if left != pair => {"))
  assert_true(source.contains("if left == meta_left_2 {"))
  assert_true(source.contains("if left != pair {"))
  assert_true(
    source.contains("if left == meta_left_2 {\n          if left != pair {"),
  )
  assert_true(source.contains("\"pair\": pair"))
  assert_true(source.contains("\"left\": left"))
}
