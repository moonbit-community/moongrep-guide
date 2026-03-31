///|
test "parse rule source reads description" {
  let source =
    #|package: moonbit-community/example
    #|description: |
    #|  Example rule description.
    #|patterns:
    #|  - shape: |
    #|      node.set_inner_html(html)
    #|    metavars:
    #|      subtree:
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
test "parse rule source rejects legacy describle key" {
  let source =
    #|package: moonbit-community/example
    #|describle: old spelling
    #|patterns:
    #|  - shape: |
    #|      @foo()
  let result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  match result {
    Err(InvalidRule(path~, info~)) => {
      inspect(path, content="references/rules/example/test.yaml")
      inspect(info, content="top-level rule contains unsupported key describle")
    }
    _ => fail("expected legacy describle key to be rejected")
  }
}

///|
test "parse rule source rejects legacy metavar bucket keys" {
  let legacy_subtree_source =
    #|package: moonbit-community/example
    #|description: legacy subtree key
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      structural:
    #|        - foo
  let legacy_identifier_source =
    #|package: moonbit-community/example
    #|description: legacy identifier key
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      subtree:
    #|        - foo
    #|      nameonly:
    #|        - bar
  let legacy_subtree_result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", legacy_subtree_source,
  )
  let legacy_identifier_result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", legacy_identifier_source,
  )
  match legacy_subtree_result {
    Err(InvalidRule(path~, info~)) => {
      inspect(path, content="references/rules/example/test.yaml")
      inspect(
        info,
        content="patterns[0].metavars contains unsupported key structural",
      )
    }
    _ => fail("expected legacy structural key to be rejected")
  }
  match legacy_identifier_result {
    Err(InvalidRule(path~, info~)) => {
      inspect(path, content="references/rules/example/test.yaml")
      inspect(
        info,
        content="patterns[0].metavars contains unsupported key nameonly",
      )
    }
    _ => fail("expected legacy nameonly key to be rejected")
  }
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
  inspect(rule.patterns[0].subtree_metavars, content="[]")
  inspect(rule.patterns[0].identifier_metavars, content="[]")
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
    #|      subtree:
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
  inspect(rule.patterns[0].identifier_metavars, content="[]")
}

///|
test "parse rule source defaults omitted identifier metavars to empty" {
  let source =
    #|package: moonbit-community/example
    #|description: subtree-only rule
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      subtree:
    #|        - foo
    #|        - bar
  let rule = parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  inspect(rule.patterns[0].subtree_metavars, content="[\"foo\", \"bar\"]")
  inspect(rule.patterns[0].identifier_metavars, content="[]")
}

///|
test "parse rule source stores identifier metavars" {
  let source =
    #|package: moonbit-community/example
    #|description: identifier rule
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      subtree:
    #|        - foo
    #|      identifier:
    #|        - bar
  let rule = parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  inspect(rule.patterns[0].subtree_metavars, content="[\"foo\"]")
  inspect(rule.patterns[0].identifier_metavars, content="[\"bar\"]")
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
    #|      subtree:
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
    #|      subtree:
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
    #|      subtree:
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
    #|      subtree:
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
test "reject invalid identifier declarations" {
  let non_array_source =
    #|package: moonbit-community/example
    #|description: invalid identifier
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      subtree:
    #|        - foo
    #|      identifier:
    #|        value: nope
  let duplicate_source =
    #|package: moonbit-community/example
    #|description: duplicate identifier
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      subtree:
    #|        - foo
    #|      identifier:
    #|        - bar
    #|        - bar
  let overlap_source =
    #|package: moonbit-community/example
    #|description: overlapping buckets
    #|patterns:
    #|  - shape: |
    #|      foo(bar)
    #|    metavars:
    #|      subtree:
    #|        - foo
    #|      identifier:
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
    #|      subtree:
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
    #|      subtree:
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
