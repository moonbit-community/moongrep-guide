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
    #|      structural:
    #|        - node
    #|        - html
  let rule = parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  inspect(rule.rule_id, content="example/test")
  inspect(rule.package_name, content="moonbit-community/example")
  inspect(rule.description, content="Example rule description.\n")
}

///|
test "parse rule source defaults omitted metavars to empty" {
  let source =
    #|package: moonbit-community/example
    #|description: no metavars rule
    #|patterns:
    #|  - shape: |
    #|      @foo()
  let rule = parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  inspect(rule.patterns[0].structural_metavars, content="[]")
  inspect(rule.patterns[0].nameonly_metavars, content="[]")
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
    #|      structural:
    #|        - foo
    #|        - bar
    #|    guard: |
    #|      
    #|      bar != foo
    #|      
  let rule = parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  inspect(rule.patterns[0].pattern_guard, content="Some(\"bar != foo\")")
  inspect(rule.patterns[0].nameonly_metavars, content="[]")
}

///|
test "parse rule source defaults omitted nameonly metavars to empty" {
  let source =
    #|package: moonbit-community/example
    #|description: structural-only rule
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      structural:
    #|        - foo
    #|        - bar
  let rule = parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  inspect(rule.patterns[0].structural_metavars, content="[\"foo\", \"bar\"]")
  inspect(rule.patterns[0].nameonly_metavars, content="[]")
}

///|
test "parse rule source stores nameonly metavars" {
  let source =
    #|package: moonbit-community/example
    #|description: nameonly rule
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      structural:
    #|        - foo
    #|      nameonly:
    #|        - bar
  let rule = parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  inspect(rule.patterns[0].structural_metavars, content="[\"foo\"]")
  inspect(rule.patterns[0].nameonly_metavars, content="[\"bar\"]")
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
    #|      structural:
    #|        - bar
    #|        - bar
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
    #|      structural:
    #|        - foo
    #|        - bar
    #|    guard:
    #|      value: nope
  let blank_source =
    #|package: moonbit-community/example
    #|description: guarded rule
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      structural:
    #|        - foo
    #|        - bar
    #|    guard: |
    #|      
  let invalid_source =
    #|package: moonbit-community/example
    #|description: guarded rule
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      structural:
    #|        - foo
    #|        - bar
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
test "reject invalid nameonly declarations" {
  let non_array_source =
    #|package: moonbit-community/example
    #|description: invalid nameonly
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      structural:
    #|        - foo
    #|      nameonly:
    #|        value: nope
  let duplicate_source =
    #|package: moonbit-community/example
    #|description: duplicate nameonly
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      structural:
    #|        - foo
    #|      nameonly:
    #|        - bar
    #|        - bar
  let overlap_source =
    #|package: moonbit-community/example
    #|description: overlapping buckets
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      structural:
    #|        - foo
    #|      nameonly:
    #|        - foo
  let non_array_result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", non_array_source,
  )
  let duplicate_result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", duplicate_source,
  )
  let overlap_result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", overlap_source,
  )
  assert_true(non_array_result is Err(_))
  assert_true(duplicate_result is Err(_))
  assert_true(overlap_result is Err(_))
}

///|
test "reject invalid metavars mapping" {
  let source =
    #|package: moonbit-community/example
    #|description: invalid metavars mapping
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      - foo
    #|      - bar
  let result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  assert_true(result is Err(_))
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
    #|      structural:
    #|        - foo
    #|        - file
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

///|
test "reject reserved generated-local prefix in metavars" {
  let source =
    #|package: moonbit-community/example
    #|description: invalid metavar prefix
    #|patterns:
    #|  - shape: |
    #|      foo(__moongrep_counter)
    #|    metavars:
    #|      structural:
    #|        - foo
    #|        - __moongrep_counter
  let result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  match result {
    Err(InvalidRule(path~, info~)) => {
      inspect(path, content="references/rules/example/test.yaml")
      inspect(
        info,
        content="patterns[0] cannot declare metavar __moongrep_counter because names starting with __moongrep_ are reserved for generated matcher locals",
      )
    }
    _ => fail("expected generated matcher local prefix conflict")
  }
}
