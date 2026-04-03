///|
fn assert_invalid_rule(
  err : Error,
  path_content : String,
  info_content : String,
) -> Unit raise {
  let message = err.to_string()
  assert_true(message.contains(path_content))
  assert_true(message.contains(info_content))
}

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
          subtree_metavars: ["node", "html"],
          identifier_metavars: [],
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
test "emit matcher source marks bundled rule functions as raising" {
  let source = emit_matcher_source([
    {
      rule_id: "example/test",
      package_name: "moonbit-community/example",
      description: "example rule",
      patterns: [
        {
          shape: "node.set_inner_html(html)",
          subtree_metavars: ["node", "html"],
          identifier_metavars: [],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_true(
    source.contains(
      "#warnings(\"-unused_error_type\")\nfn example_test(file : String, ast : Json, hits : Array[MatchHit]) -> Bool raise {",
    ),
  )
  assert_true(
    source.contains(
      "pub let moongrep_rules_table : Map[String, (String, Json, Array[MatchHit]) -> Bool raise] = {",
    ),
  )
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
          subtree_metavars: ["node", "html"],
          identifier_metavars: [],
          pattern_guard: None,
        },
        {
          shape: "node.set_outer_html(html)",
          subtree_metavars: ["node", "html"],
          identifier_metavars: [],
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
          subtree_metavars: ["value", "args"],
          identifier_metavars: [],
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
          subtree_metavars: ["node", "html"],
          identifier_metavars: [],
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
    Err(err) =>
      assert_invalid_rule(
        err, "example/a_b", "rule matcher function name conflict: example/a-b and example/a_b both map to example_a_b",
      )
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
          subtree_metavars: ["pair", "left"],
          identifier_metavars: [],
          pattern_guard: Some("left != pair"),
        },
      ],
    },
  ])
  assert_true(
    source.contains(
      "} if @greptools.normalize_structural_json(left) == @greptools.normalize_structural_json(meta_left_2) && (left != pair) => {",
    ),
  )
  assert_false(source.contains("\"pair\": pair"))
  assert_false(source.contains("\"left\": left"))
  assert_false(source.contains("bindings:"))
}

///|
test "emit matcher source normalizes identifier metavars before guard" {
  let source = emit_matcher_source([
    {
      rule_id: "example/identifier-guarded",
      package_name: "moonbit-community/example",
      description: "identifier guarded rule",
      patterns: [
        {
          shape: "for counter = start; counter < limit; counter = next { body }",
          subtree_metavars: ["start", "limit", "next", "body"],
          identifier_metavars: ["counter"],
          pattern_guard: Some("@greptools.example(counter, next, body)"),
        },
      ],
    },
  ])
  assert_true(
    source.contains(
      "fn __moongrep_guard_0(start : Json, limit : Json, next : Json, body : Json, counter : String) -> Bool raise {",
    ),
  )
  assert_true(
    source.contains(
      "} if @greptools.normalize_identifier_name(counter) is Some(__moongrep_identifier_name_meta_counter_1) && @greptools.normalize_identifier_name(meta_counter_2) is Some(__moongrep_identifier_name_meta_counter_2) && @greptools.normalize_identifier_name(meta_counter_3) is Some(__moongrep_identifier_name_meta_counter_3) && __moongrep_identifier_name_meta_counter_1 == __moongrep_identifier_name_meta_counter_2 && __moongrep_identifier_name_meta_counter_1 == __moongrep_identifier_name_meta_counter_3 && __moongrep_guard_0(start, limit, next, body, __moongrep_identifier_name_meta_counter_1) => {",
    ),
  )
  assert_false(source.contains("let __moongrep_identifier_opt_meta_counter_1"))
  assert_false(
    source.contains("match (__moongrep_identifier_opt_meta_counter_1"),
  )
}

///|
test "emit matcher source checks identifier normalization without guard" {
  let source = emit_matcher_source([
    {
      rule_id: "example/identifier",
      package_name: "moonbit-community/example",
      description: "identifier rule",
      patterns: [
        {
          shape: "pair(left, right)",
          subtree_metavars: ["pair", "right"],
          identifier_metavars: ["left"],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_true(
    source.contains(
      "} if @greptools.normalize_identifier_name(left) is Some(__moongrep_identifier_name_meta_left_1) => {",
    ),
  )
  assert_false(source.contains("fn __moongrep_guard("))
}

///|
test "emit matcher source captures identifier metavars in Var targets" {
  let source = emit_matcher_source([
    {
      rule_id: "example/assignment-target",
      package_name: "moonbit-community/example",
      description: "assignment target identifier rule",
      patterns: [
        {
          shape: "variable = variable + value",
          subtree_metavars: ["value"],
          identifier_metavars: ["variable"],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_true(source.contains("\"var\": variable"))
  assert_true(
    source.contains(
      "@greptools.normalize_identifier_name(variable) is Some(__moongrep_identifier_name_meta_variable_1)",
    ),
  )
  assert_true(
    source.contains(
      "@greptools.normalize_identifier_name(meta_variable_2) is Some(__moongrep_identifier_name_meta_variable_2)",
    ),
  )
}

///|
test "emit matcher source captures identifier metavars in field Labels" {
  let source = emit_matcher_source([
    {
      rule_id: "example/mutate-field",
      package_name: "moonbit-community/example",
      description: "field mutate identifier rule",
      patterns: [
        {
          shape: "record.field = record.field + value",
          subtree_metavars: ["record", "value"],
          identifier_metavars: ["field"],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_true(source.contains("\"value\": field"))
  assert_true(
    source.contains(
      "@greptools.normalize_identifier_name(field) is Some(__moongrep_identifier_name_meta_field_1)",
    ),
  )
  assert_true(
    source.contains(
      "@greptools.normalize_identifier_name(meta_field_2) is Some(__moongrep_identifier_name_meta_field_2)",
    ),
  )
  assert_true(
    source.contains(
      "@greptools.normalize_structural_json(record) == @greptools.normalize_structural_json(meta_record_2)",
    ),
  )
  assert_true(
    source.contains(
      "__moongrep_identifier_name_meta_field_1 == __moongrep_identifier_name_meta_field_2",
    ),
  )
}

///|
test "emit matcher source captures identifier metavars in method Labels" {
  let source = emit_matcher_source([
    {
      rule_id: "example/dot-apply",
      package_name: "moonbit-community/example",
      description: "method label identifier rule",
      patterns: [
        {
          shape: "receiver.method()",
          subtree_metavars: ["receiver"],
          identifier_metavars: ["method"],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_true(source.contains("\"method_name\": method"))
  assert_true(
    source.contains(
      "@greptools.normalize_identifier_name(method) is Some(__moongrep_identifier_name_meta_method_1)",
    ),
  )
}

///|
test "emit matcher source uses unique helper names per guarded identifier pattern" {
  let source = emit_matcher_source([
    {
      rule_id: "example/multi-guarded",
      package_name: "moonbit-community/example",
      description: "multi guarded rule",
      patterns: [
        {
          shape: "for counter = start; counter < limit; counter = next { body }",
          subtree_metavars: ["start", "limit", "next", "body"],
          identifier_metavars: ["counter"],
          pattern_guard: Some("@greptools.example(counter, next, body)"),
        },
        {
          shape: "for index = begin; index < end_; index = step { body2 }",
          subtree_metavars: ["begin", "end_", "step", "body2"],
          identifier_metavars: ["index"],
          pattern_guard: Some("@greptools.example(index, step, body2)"),
        },
      ],
    },
  ])
  assert_true(
    source.contains(
      "fn __moongrep_guard_0(start : Json, limit : Json, next : Json, body : Json, counter : String) -> Bool raise {",
    ),
  )
  assert_true(
    source.contains(
      "fn __moongrep_guard_1(begin : Json, end_ : Json, step : Json, body2 : Json, index : String) -> Bool raise {",
    ),
  )
}

///|
test "emit matcher source treats built-in ignore placeholder as expr wildcard" {
  let source = emit_matcher_source([
    {
      rule_id: "example/ignore-expr",
      package_name: "moonbit-community/example",
      description: "ignore expr rule",
      patterns: [
        {
          shape: "foo(__)",
          subtree_metavars: [],
          identifier_metavars: [],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_true(source.contains("\"value\": _"))
  assert_false(source.contains("\"value\": \"__\""))
  assert_false(source.contains("meta___"))
}

///|
test "emit matcher source treats built-in ignore placeholder as Var wildcard" {
  let source = emit_matcher_source([
    {
      rule_id: "example/ignore-var",
      package_name: "moonbit-community/example",
      description: "ignore assignment target",
      patterns: [
        {
          shape: "____ = value",
          subtree_metavars: [],
          identifier_metavars: [],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_true(source.contains("\"var\": _"))
  assert_false(source.contains("@greptools.normalize_identifier_name("))
  assert_false(source.contains("meta_____"))
}

///|
test "emit matcher source treats repeated built-in ignore placeholders independently" {
  let source = emit_matcher_source([
    {
      rule_id: "example/ignore-binder",
      package_name: "moonbit-community/example",
      description: "ignore repeated binder",
      patterns: [
        {
          shape: "for __ = start; ____ < limit; _____ = next { body }",
          subtree_metavars: [],
          identifier_metavars: [],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_false(source.contains("} if "))
  assert_false(source.contains("\"name\": \"__\""))
  assert_false(source.contains("\"name\": \"____\""))
  assert_false(source.contains("\"name\": \"_____\""))
}

///|
test "emit matcher source treats built-in ignore placeholder as pattern wildcard" {
  let source = emit_matcher_source([
    {
      rule_id: "example/ignore-pattern",
      package_name: "moonbit-community/example",
      description: "ignore pattern",
      patterns: [
        {
          shape: "match value { __ => body }",
          subtree_metavars: [],
          identifier_metavars: [],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_true(source.contains("\"pattern\": _"))
  assert_false(source.contains("\"name\": \"___\""))
  assert_false(source.contains("meta____"))
}

///|
test "emit matcher source treats built-in ignore placeholder as Label wildcard" {
  let source = emit_matcher_source([
    {
      rule_id: "example/ignore-label",
      package_name: "moonbit-community/example",
      description: "ignore label",
      patterns: [
        {
          shape: "foo.__()",
          subtree_metavars: [],
          identifier_metavars: [],
          pattern_guard: None,
        },
      ],
    },
  ])
  assert_true(source.contains("\"method_name\": _"))
  assert_false(source.contains("\"name\": \"__\""))
}
