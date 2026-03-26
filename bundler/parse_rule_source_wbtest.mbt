///|
test "parse rule source supports describle" {
  let source =
    #|package: moonbit-community/example
    #|describle: |
    #|  Example rule description.
    #|patterns:
    #|  - shape: |
    #|      node.set_inner_html(html)
    #|    metavars:
    #|      - node
    #|      - html
  let rule = parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  inspect(rule.rule_id, content="example/test")
  inspect(rule.package_name, content="moonbit-community/example")
  inspect(rule.description, content="Example rule description.\n")
}

///|
test "parse rule source stores trimmed pattern guard" {
  let source =
    #|package: moonbit-community/example
    #|description: guarded rule
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      - foo
    #|      - bar
    #|    guard: |
    #|      
    #|      bar != foo
    #|      
  let rule = parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  inspect(rule.patterns[0].pattern_guard, content="Some(\"bar != foo\")")
}

///|
test "reject duplicate metavars" {
  let source =
    #|package: moonbit-community/example
    #|description: duplicate metavars
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      - bar
    #|      - bar
  let result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  assert_true(result is Err(_))
}

///|
test "reject non-string blank and invalid pattern guard" {
  let non_string_source =
    #|package: moonbit-community/example
    #|description: guarded rule
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      - foo
    #|      - bar
    #|    guard:
    #|      value: nope
  let blank_source =
    #|package: moonbit-community/example
    #|description: guarded rule
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      - foo
    #|      - bar
    #|    guard: |
    #|      
  let invalid_source =
    #|package: moonbit-community/example
    #|description: guarded rule
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      - foo
    #|      - bar
    #|    guard: |
    #|      (foo +
  let non_string_result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", non_string_source,
  )
  let blank_result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", blank_source,
  )
  let invalid_result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", invalid_source,
  )
  assert_true(non_string_result is Err(_))
  assert_true(blank_result is Err(_))
  assert_true(invalid_result is Err(_))
}

///|
test "reject reserved metavars that conflict with generated locals" {
  let source =
    #|package: moonbit-community/example
    #|description: invalid metavar
    #|patterns:
    #|  - shape: |
    #|      foo(file)
    #|    metavars:
    #|      - foo
    #|      - file
  let result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  match result {
    Err(InvalidRule(path~, info~)) => {
      inspect(path, content="references/rules/example/test.yaml")
      inspect(
        info,
        content="patterns[0] cannot declare metavar file because it conflicts with generated matcher locals",
      )
    }
    _ => fail("expected generated matcher local conflict")
  }
}
