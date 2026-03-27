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
          structural_metavars: ["node", "html"],
          nameonly_metavars: [],
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
          structural_metavars: ["node", "html"],
          nameonly_metavars: [],
          pattern_guard: None,
        },
        {
          shape: "node.set_outer_html(html)",
          structural_metavars: ["node", "html"],
          nameonly_metavars: [],
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
          structural_metavars: ["value", "args"],
          nameonly_metavars: [],
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
test "emit matcher source does not capture metavars in match hits" {
  let source = emit_matcher_source([
    {
      rule_id: "example/test",
      package_name: "moonbit-community/example",
      description: "example rule",
      patterns: [
        {
          shape: "node.set_inner_html(html)",
          structural_metavars: ["node", "html"],
          nameonly_metavars: [],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_true(source.contains("\"self\": node"))
  assert_true(source.contains("\"value\": html"))
  assert_false(source.contains("\"node\": node"))
  assert_false(source.contains("\"html\": html"))
  assert_false(source.contains("bindings:"))
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
          structural_metavars: ["pair", "left"],
          nameonly_metavars: [],
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
  assert_false(source.contains("\"pair\": pair"))
  assert_false(source.contains("\"left\": left"))
  assert_false(source.contains("bindings:"))
}

///|
test "emit matcher source normalizes nameonly metavars before guard" {
  let source = emit_matcher_source([
    {
      rule_id: "example/name-only-guarded",
      package_name: "moonbit-community/example",
      description: "name-only guarded rule",
      patterns: [
        {
          shape: "for counter = start; counter < limit; counter = next { body }",
          structural_metavars: ["start", "limit", "next", "body"],
          nameonly_metavars: ["counter"],
          pattern_guard: Some("@greptools.example(counter, next, body)"),
        },
      ],
    },
  ])
  assert_true(
    source.contains(
      "let __moongrep_name_opt_meta_counter_1 = @greptools.normalize_metavar_name(counter)",
    ),
  )
  assert_true(
    source.contains(
      "let __moongrep_name_opt_meta_counter_2 = @greptools.normalize_metavar_name(meta_counter_2)",
    ),
  )
  assert_true(
    source.contains(
      "match (__moongrep_name_opt_meta_counter_1, __moongrep_name_opt_meta_counter_2, __moongrep_name_opt_meta_counter_3)",
    ),
  )
  assert_true(
    source.contains(
      "(Some(__moongrep_name_meta_counter_1), Some(__moongrep_name_meta_counter_2), Some(__moongrep_name_meta_counter_3)) => {",
    ),
  )
  assert_true(
    source.contains(
      "fn __moongrep_guard(start : Json, limit : Json, next : Json, body : Json, counter : String) -> Bool {",
    ),
  )
  assert_true(
    source.contains(
      "if __moongrep_name_meta_counter_1 == __moongrep_name_meta_counter_2 && __moongrep_name_meta_counter_1 == __moongrep_name_meta_counter_3 {",
    ),
  )
  assert_true(
    source.contains(
      "if __moongrep_guard(start, limit, next, body, __moongrep_name_meta_counter_1) {",
    ),
  )
}

///|
test "emit matcher source checks nameonly normalization without guard" {
  let source = emit_matcher_source([
    {
      rule_id: "example/name-only",
      package_name: "moonbit-community/example",
      description: "name-only rule",
      patterns: [
        {
          shape: "pair(left, right)",
          structural_metavars: ["pair", "right"],
          nameonly_metavars: ["left"],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_true(
    source.contains(
      "let __moongrep_name_opt_meta_left_1 = @greptools.normalize_metavar_name(left)",
    ),
  )
  assert_true(source.contains("match __moongrep_name_opt_meta_left_1 {"))
  assert_true(source.contains("Some(__moongrep_name_meta_left_1) => {"))
  assert_false(source.contains("fn __moongrep_guard("))
}
