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
fn pattern_spec(
  shape : String,
  subtree_metavars : Array[String],
  identifier_metavars : Array[String],
  pattern_guard : String?,
) -> @spec.RulePatternSpec {
  { shape, subtree_metavars, identifier_metavars, pattern_guard }
}

///|
fn structural_rule(
  rule_id : String,
  package_name : String,
  description : String,
  patterns : Array[@spec.RulePatternSpec],
) -> @spec.RuleSpec {
  {
    rule_id,
    package_name,
    description,
    definition: @spec.RuleDefinitionSpec::Structural(patterns),
  }
}

///|
fn structural_emit_rule(
  rule_id : String,
  package_name : String,
  description : String,
  patterns : Array[@spec.RulePatternSpec],
) -> StructuralEmitRule {
  {
    rule: structural_rule(rule_id, package_name, description, patterns),
    patterns,
  }
}

///|
fn taint_rule(
  rule_id : String,
  package_name : String,
  description : String,
  sources : Array[@spec.RulePatternSpec],
  sinks : Array[@spec.RulePatternSpec],
  sanitizers : Array[@spec.RulePatternSpec],
) -> @spec.RuleSpec {
  {
    rule_id,
    package_name,
    description,
    definition: @spec.RuleDefinitionSpec::Taint({ sources, sinks, sanitizers }),
  }
}

///|
test "emit bundle source builds package-local matcher file" {
  let source = emit_bundle_source([
    structural_rule(
      "example/test",
      "moonbit-community/example",
      "example rule",
      [pattern_spec("node.set_inner_html(html)", ["node", "html"], [], None)],
    ),
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
    structural_rule(
      "example/test",
      "moonbit-community/example",
      "example rule",
      [pattern_spec("node.set_inner_html(html)", ["node", "html"], [], None)],
    ),
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
    structural_rule(
      "example/first",
      "moonbit-community/example",
      "first rule",
      [
        pattern_spec("node.set_inner_html(html)", ["node", "html"], [], None),
        pattern_spec("node.set_outer_html(html)", ["node", "html"], [], None),
      ],
    ),
    structural_rule(
      "example/second",
      "moonbit-community/example",
      "second rule",
      [pattern_spec("value.apply(args)", ["value", "args"], [], None)],
    ),
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
    structural_rule(
      "example/test",
      "moonbit-community/example",
      "example rule",
      [pattern_spec("node.set_inner_html(html)", ["node", "html"], [], None)],
    ),
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
    structural_emit_rule(
      "example/a-b",
      "moonbit-community/example",
      "first rule",
      [],
    ),
    structural_emit_rule(
      "example/a_b",
      "moonbit-community/example",
      "second rule",
      [],
    ),
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
    structural_rule(
      "example/guarded",
      "moonbit-community/example",
      "guarded rule",
      [
        pattern_spec(
          "pair(left, left)",
          ["pair", "left"],
          [],
          Some("left != pair"),
        ),
      ],
    ),
  ])
  assert_true(
    source.contains(
      "} if @greptools.ast_json_repr_equal(left, meta_left_2) && (left != pair) => {",
    ),
  )
  assert_false(source.contains("\"pair\": pair"))
  assert_false(source.contains("\"left\": left"))
  assert_false(source.contains("bindings:"))
}

///|
test "emit matcher source normalizes identifier metavars before guard" {
  let source = emit_matcher_source([
    structural_rule(
      "example/identifier-guarded",
      "moonbit-community/example",
      "identifier guarded rule",
      [
        pattern_spec(
          "for counter = start; counter < limit; counter = next { body }",
          ["start", "limit", "next", "body"],
          ["counter"],
          Some("@greptools.example(counter, next, body)"),
        ),
      ],
    ),
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
    structural_rule(
      "example/identifier",
      "moonbit-community/example",
      "identifier rule",
      [pattern_spec("pair(left, right)", ["pair", "right"], ["left"], None)],
    ),
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
    structural_rule(
      "example/assignment-target",
      "moonbit-community/example",
      "assignment target identifier rule",
      [
        pattern_spec(
          "variable = variable + value",
          ["value"],
          ["variable"],
          None,
        ),
      ],
    ),
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
    structural_rule(
      "example/mutate-field",
      "moonbit-community/example",
      "field mutate identifier rule",
      [
        pattern_spec(
          "record.field = record.field + value",
          ["record", "value"],
          ["field"],
          None,
        ),
      ],
    ),
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
    source.contains("@greptools.ast_json_repr_equal(record, meta_record_2)"),
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
    structural_rule(
      "example/dot-apply",
      "moonbit-community/example",
      "method label identifier rule",
      [pattern_spec("receiver.method()", ["receiver"], ["method"], None)],
    ),
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
    structural_rule(
      "example/multi-guarded",
      "moonbit-community/example",
      "multi guarded rule",
      [
        pattern_spec(
          "for counter = start; counter < limit; counter = next { body }",
          ["start", "limit", "next", "body"],
          ["counter"],
          Some("@greptools.example(counter, next, body)"),
        ),
        pattern_spec(
          "for index = begin; index < end_; index = step { body2 }",
          ["begin", "end_", "step", "body2"],
          ["index"],
          Some("@greptools.example(index, step, body2)"),
        ),
      ],
    ),
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
    structural_rule(
      "example/ignore-expr",
      "moonbit-community/example",
      "ignore expr rule",
      [pattern_spec("foo(__)", [], [], None)],
    ),
  ])
  assert_true(source.contains("\"value\": _"))
  assert_false(source.contains("\"value\": \"__\""))
  assert_false(source.contains("meta___"))
}

///|
test "emit matcher source treats built-in ignore placeholder as Var wildcard" {
  let source = emit_matcher_source([
    structural_rule(
      "example/ignore-var",
      "moonbit-community/example",
      "ignore assignment target",
      [pattern_spec("____ = value", [], [], None)],
    ),
  ])
  assert_true(source.contains("\"var\": _"))
  assert_false(source.contains("@greptools.normalize_identifier_name("))
  assert_false(source.contains("meta_____"))
}

///|
test "emit matcher source treats repeated built-in ignore placeholders independently" {
  let source = emit_matcher_source([
    structural_rule(
      "example/ignore-binder",
      "moonbit-community/example",
      "ignore repeated binder",
      [
        pattern_spec(
          "for __ = start; ____ < limit; _____ = next { body }",
          [],
          [],
          None,
        ),
      ],
    ),
  ])
  assert_false(source.contains("} if "))
  assert_false(source.contains("\"name\": \"__\""))
  assert_false(source.contains("\"name\": \"____\""))
  assert_false(source.contains("\"name\": \"_____\""))
}

///|
test "emit matcher source treats built-in ignore placeholder as pattern wildcard" {
  let source = emit_matcher_source([
    structural_rule(
      "example/ignore-pattern",
      "moonbit-community/example",
      "ignore pattern",
      [pattern_spec("match value { __ => body }", [], [], None)],
    ),
  ])
  assert_true(source.contains("\"pattern\": _"))
  assert_false(source.contains("\"name\": \"___\""))
  assert_false(source.contains("meta____"))
}

///|
test "emit matcher source treats built-in ignore placeholder as Label wildcard" {
  let source = emit_matcher_source([
    structural_rule(
      "example/ignore-label",
      "moonbit-community/example",
      "ignore label",
      [pattern_spec("foo.__()", [], [], None)],
    ),
  ])
  assert_true(source.contains("\"method_name\": _"))
  assert_false(source.contains("\"name\": \"__\""))
}

///|
test "emit bundle source exports bundled taint rules" {
  let source = emit_bundle_source([
    taint_rule(
      "example/taint",
      "moonbit-community/example",
      "taint rule",
      [pattern_spec("__test_taint_source()", [], [], None)],
      [pattern_spec("__test_taint_sink(__SOURCE__)", [], [], None)],
      [],
    ),
  ])
  assert_true(source.contains("fn example_taint__taint_custom"))
  assert_true(
    source.contains("pub let moongrep_taint_rules : Array[BundledTaintRule]"),
  )
  assert_true(
    source.contains("custom_transfer_call: example_taint__taint_custom"),
  )
  assert_true(source.contains("sink_ids: [\"sink:0\"]"))
}

///|
test "emit taint bundle source lowers source sink and sanitizer clauses" {
  let source = emit_taint_bundle_source([
    taint_rule(
      "example/taint-flow",
      "moonbit-community/example",
      "taint flow rule",
      [pattern_spec("__test_taint_source()", [], [], None)],
      [pattern_spec("__test_taint_sink(__SOURCE__)", [], [], None)],
      [pattern_spec("__test_taint_sanitize(__SOURCE__)", [], [], None)],
    ),
  ])
  assert_true(
    source.contains(
      "merge_taint_tree_into(return_taint, fresh_call_return_taint(info, \"example/taint-flow\", \"source:0\"))",
    ),
  )
  assert_true(
    source.contains(
      "Some(argument) => add_sink_finding_if_tainted(findings, \"example/taint-flow\", \"sink:0\", info.loc, argument.site, argument.taint)",
    ),
  )
  assert_true(
    source.contains("Some(path) => add_storage_path_unique(killed_paths, path)"),
  )
}

///|
test "emit taint bundle source supports identifier metavars" {
  let source = emit_taint_bundle_source([
    taint_rule(
      "example/taint-method",
      "moonbit-community/example",
      "taint method rule",
      [pattern_spec("__test_taint_source()", [], [], None)],
      [
        pattern_spec(
          "receiver.method(__SOURCE__)",
          ["receiver"],
          ["method"],
          None,
        ),
      ],
      [],
    ),
  ])
  assert_true(source.contains("\"self\": receiver"))
  assert_true(source.contains("\"method_name\": method"))
  assert_true(
    source.contains(
      "@greptools.normalize_identifier_name(method) is Some(__moongrep_identifier_name_meta_method_1)",
    ),
  )
}

///|
test "emit taint bundle source rejects reserved source placeholder in sources" {
  let result = try? emit_taint_bundle_source([
    taint_rule(
      "example/taint-invalid-source",
      "moonbit-community/example",
      "invalid taint source",
      [pattern_spec("__test_taint_source(__SOURCE__)", [], [], None)],
      [pattern_spec("__test_taint_sink(__SOURCE__)", [], [], None)],
      [],
    ),
  ])
  match result {
    Err(err) =>
      assert_invalid_rule(
        err, "example/taint-invalid-source", "taint.sources[0] must not contain __SOURCE__",
      )
    _ => fail("expected taint source placeholder rejection")
  }
}

///|
test "emit taint bundle source rejects nested source placeholder" {
  let result = try? emit_taint_bundle_source([
    taint_rule(
      "example/taint-invalid-target",
      "moonbit-community/example",
      "invalid taint target",
      [pattern_spec("__test_taint_source()", [], [], None)],
      [pattern_spec("__test_taint_sink(wrap(__SOURCE__))", [], [], None)],
      [],
    ),
  ])
  match result {
    Err(err) =>
      assert_invalid_rule(
        err, "example/taint-invalid-target", "taint.sinks[0] must place __SOURCE__ as the entire receiver or argument value",
      )
    _ => fail("expected nested taint target rejection")
  }
}
