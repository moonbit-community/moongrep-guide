///|
suberror RuleBundleError {
  InvalidRule(path~ : String, info~ : String)
} derive(Show)

///|
struct RulePatternSpec {
  shape : String
  metavars : Array[String]
  pattern_guard : String?
}

///|
struct RuleSpec {
  rule_id : String
  package_name : String
  description : String
  patterns : Array[RulePatternSpec]
}

///|
struct BindingRecord {
  meta_name : String
  bind_names : Array[String]
}

///|
struct PatternEmitContext {
  declared_metavars : Array[String]
  bindings : Array[BindingRecord]
  expose_metavar_names : Bool
}

///|
let default_rules_root = "rules"

///|
let default_output_path = "moongrep/bundled_rules.mbt"

///|
pub fn generate_bundle_source(
  rules_root? : String = default_rules_root,
) -> String raise {
  let rules = load_rules(rules_root)
  emit_bundle_source(rules)
}

///|
pub fn write_bundle(
  rules_root? : String = default_rules_root,
  output_path? : String = default_output_path,
) -> Unit raise {
  let source = generate_bundle_source(rules_root~)
  @fs.write_string_to_file(output_path, source)
}

///|
fn load_rules(rules_root : String) -> Array[RuleSpec] raise {
  let files = collect_rule_files(rules_root)
  if files.is_empty() {
    raise InvalidRule(path=rules_root, info="no YAML rule files found")
  }
  let rules : Array[RuleSpec] = []
  for file in files {
    let source = @fs.read_file_to_string(file)
    rules.push(parse_rule_source(file, rules_root, source))
  }
  rules
}

///|
fn collect_rule_files(rules_root : String) -> Array[String] raise {
  let files : Array[String] = []
  walk_rule_dir(rules_root, files)
  files.sort()
  files
}

///|
fn walk_rule_dir(dir : String, files : Array[String]) -> Unit raise {
  let entries = @fs.read_dir(dir)
  entries.sort()
  for entry in entries {
    let path = "\{dir}/\{entry}"
    if @fs.is_dir(path) {
      walk_rule_dir(path, files)
    } else if has_yaml_suffix(path) {
      files.push(path)
    }
  }
}

///|
fn has_yaml_suffix(path : String) -> Bool {
  path.has_suffix(".yaml") || path.has_suffix(".yml")
}

///|
fn parse_rule_source(
  path : String,
  rules_root : String,
  source : String,
) -> RuleSpec raise {
  let docs = @yaml.Yaml::load_from_string(source)
  if docs.length() != 1 {
    raise InvalidRule(
      path~,
      info="rule file must contain exactly one YAML document",
    )
  }
  guard docs[0] is @yaml.Yaml::Map(doc) else {
    raise InvalidRule(path~, info="top-level YAML document must be a mapping")
  }
  ensure_allowed_keys(path, "top-level rule", doc, [
    "package", "description", "describle", "patterns",
  ])
  let package_name = expect_yaml_string(doc, path, "package")
  let description = expect_description(doc, path)
  let patterns_yaml = expect_yaml_array(doc, path, "patterns")
  if patterns_yaml.is_empty() {
    raise InvalidRule(path~, info="patterns must not be empty")
  }
  let patterns : Array[RulePatternSpec] = []
  for index in 0..<patterns_yaml.length() {
    let pattern_yaml = patterns_yaml[index]
    guard pattern_yaml is @yaml.Yaml::Map(pattern_map) else {
      raise InvalidRule(path~, info="patterns[\{index}] must be a mapping")
    }
    ensure_allowed_keys(path, "pattern[\{index}]", pattern_map, [
      "shape", "metavars", "guard",
    ])
    let shape = expect_yaml_string(pattern_map, path, "shape")
    let metavars_yaml = expect_yaml_array(pattern_map, path, "metavars")
    let metavars : Array[String] = []
    for meta_index in 0..<metavars_yaml.length() {
      guard metavars_yaml[meta_index] is @yaml.Yaml::String(meta_name) else {
        raise InvalidRule(
          path~,
          info="patterns[\{index}].metavars[\{meta_index}] must be a string",
        )
      }
      if metavars.contains(meta_name) {
        raise InvalidRule(
          path~,
          info="patterns[\{index}] contains duplicate metavar \{meta_name}",
        )
      }
      metavars.push(meta_name)
    }
    let pattern_guard = expect_pattern_guard(pattern_map, path, index, metavars)
    patterns.push({ shape, metavars, pattern_guard })
  }
  {
    rule_id: rule_id_from_path(path, rules_root),
    package_name,
    description,
    patterns,
  }
}

///|
fn ensure_allowed_keys(
  path : String,
  context : String,
  map : Map[String, @yaml.Yaml],
  allowed : Array[String],
) -> Unit raise {
  for entry in map.iter() {
    if !allowed.contains(entry.0) {
      raise InvalidRule(
        path~,
        info="\{context} contains unsupported key \{entry.0}",
      )
    }
  }
}

///|
fn expect_yaml_string(
  map : Map[String, @yaml.Yaml],
  path : String,
  key : String,
) -> String raise {
  match map.get(key) {
    Some(@yaml.Yaml::String(value)) => value
    Some(_) => raise InvalidRule(path~, info="\{key} must be a string")
    None => raise InvalidRule(path~, info="missing required key \{key}")
  }
}

///|
fn expect_yaml_array(
  map : Map[String, @yaml.Yaml],
  path : String,
  key : String,
) -> Array[@yaml.Yaml] raise {
  match map.get(key) {
    Some(@yaml.Yaml::Array(values)) => values
    Some(_) => raise InvalidRule(path~, info="\{key} must be an array")
    None => raise InvalidRule(path~, info="missing required key \{key}")
  }
}

///|
fn expect_description(
  map : Map[String, @yaml.Yaml],
  path : String,
) -> String raise {
  match map.get("description") {
    Some(@yaml.Yaml::String(value)) => value
    Some(_) => raise InvalidRule(path~, info="description must be a string")
    None =>
      match map.get("describle") {
        Some(@yaml.Yaml::String(value)) => value
        Some(_) => raise InvalidRule(path~, info="describle must be a string")
        None =>
          raise InvalidRule(path~, info="missing required key description")
      }
  }
}

///|
fn expect_pattern_guard(
  map : Map[String, @yaml.Yaml],
  path : String,
  pattern_index : Int,
  metavars : Array[String],
) -> String? raise {
  match map.get("guard") {
    None => None
    Some(@yaml.Yaml::String(value)) => {
      let guard_source = value.trim().to_string()
      if guard_source == "" {
        raise InvalidRule(
          path~,
          info="patterns[\{pattern_index}].guard must not be blank",
        )
      }
      ensure_guard_metavars_safe(path, pattern_index, metavars)
      validate_guard_source(path, pattern_index, guard_source)
      Some(guard_source)
    }
    Some(_) =>
      raise InvalidRule(
        path~,
        info="patterns[\{pattern_index}].guard must be a string",
      )
  }
}

///|
fn ensure_guard_metavars_safe(
  path : String,
  pattern_index : Int,
  metavars : Array[String],
) -> Unit raise {
  for meta_name in metavars {
    if meta_name == "file" || meta_name == "hits" || meta_name == "loc" {
      raise InvalidRule(
        path~,
        info="patterns[\{pattern_index}].guard cannot expose metavar \{meta_name} because it conflicts with generated matcher locals",
      )
    }
  }
}

///|
fn validate_guard_source(
  path : String,
  pattern_index : Int,
  guard_source : String,
) -> Unit raise {
  let guard_wrapper = "fn _guard_check() -> Unit {\n" +
    "  let _ = \{guard_source}\n" +
    "}\n"
  let (_program, reports) = @lexer.tokens_from_string(
      guard_wrapper,
      comment=true,
      name="pattern guard",
    ).tokens
    |> @handrolled_parser.parse()
  if reports is [err, ..] {
    raise InvalidRule(
      path~,
      info="patterns[\{pattern_index}].guard is not a valid MoonBit expression: \{err.to_json().stringify(indent=2)}",
    )
  }
}

///|
fn rule_id_from_path(path : String, rules_root : String) -> String raise {
  let prefix = "\{rules_root}/"
  if !path.has_prefix(prefix) {
    raise InvalidRule(
      path~,
      info="rule path is outside rules root \{rules_root}",
    )
  }
  let relative = path[prefix.length():].to_string()
  if relative.has_suffix(".yaml") {
    relative[0:relative.length() - 5].to_string()
  } else if relative.has_suffix(".yml") {
    relative[0:relative.length() - 4].to_string()
  } else {
    raise InvalidRule(path~, info="unsupported rule file suffix")
  }
}

///|
fn emit_bundle_source(rules : Array[RuleSpec]) -> String raise {
  let builder = StringBuilder::new()
  builder.write_string("// Generated by `moon run bundler`. DO NOT EDIT.\n")
  builder.write_string("\n")
  builder.write_string(emit_matcher_source(rules))
  builder.to_string()
}

///|
fn emit_matcher_source(rules : Array[RuleSpec]) -> String raise {
  let builder = StringBuilder::new()
  let rule_function_names = emit_rule_matcher_function_names(rules)
  for rule_index in 0..<rules.length() {
    builder.write_string(
      emit_rule_matcher_source(
        rule_function_names[rule_index],
        rules[rule_index],
      ),
    )
    builder.write_string("\n")
  }
  builder.write_string(emit_rules_table_source(rules, rule_function_names))
  builder.to_string()
}

///|
fn emit_rules_table_source(
  rules : Array[RuleSpec],
  rule_function_names : Array[String],
) -> String {
  let builder = StringBuilder::new()
  let entries : Array[String] = []
  for rule_index in 0..<rules.length() {
    entries.push(
      "  \{emit_string_literal(rules[rule_index].rule_id)}: \{rule_function_names[rule_index]}",
    )
  }
  builder.write_string("///|\n")
  builder.write_string(
    "let moongrep_rules_table : Map[String, (String, Json, Array[MatchHit]) -> Bool] = {\n",
  )
  if !entries.is_empty() {
    builder.write_string(entries.join(",\n"))
    builder.write_string("\n")
  }
  builder.write_string("}\n")
  builder.to_string()
}

///|
fn emit_rule_arm(
  rule : RuleSpec,
  pattern_index : Int,
  pattern : RulePatternSpec,
) -> String raise {
  let ast = @dump_expr.dump_expr_json_repr(pattern.shape)
  let ctx = {
    declared_metavars: pattern.metavars,
    bindings: [],
    expose_metavar_names: pattern.pattern_guard is Some(_),
  }
  let pattern_source = emit_pattern_source(ast, ctx, root=true)
  ensure_all_metavars_bound(rule.rule_id, pattern_index, pattern.metavars, ctx)
  let builder = StringBuilder::new()
  builder.write_string(
    "      // rule: \{rule.rule_id} pattern \{pattern_index}\n",
  )
  let arm_head = emit_rule_arm_head(pattern_source, pattern.pattern_guard)
  builder.write_string("      \{arm_head} => {\n")
  let duplicate_condition = emit_duplicate_condition(ctx)
  let push_source = emit_push_source(rule, pattern_index, ctx)
  if duplicate_condition == "" {
    builder.write_string("        \{push_source}\n")
  } else {
    builder.write_string("        if \{duplicate_condition} {\n")
    builder.write_string("          \{push_source}\n")
    builder.write_string("        }\n")
  }
  builder.write_string("        true\n")
  builder.write_string("      }\n")
  builder.to_string()
}

///|
fn emit_rule_matcher_source(
  rule_function_name : String,
  rule : RuleSpec,
) -> String raise {
  let builder = StringBuilder::new()
  builder.write_string("///|\n")
  builder.write_string("// bundled rule: \{rule.rule_id}\n")
  builder.write_string(
    "fn \{rule_function_name}(file : String, ast : Json, hits : Array[MatchHit]) -> Bool {\n",
  )
  builder.write_string("  match ast {\n")
  for pattern_index in 0..<rule.patterns.length() {
    let pattern = rule.patterns[pattern_index]
    let arm = emit_rule_arm(rule, pattern_index, pattern)
    builder.write_string(arm)
  }
  builder.write_string("    _ => true\n")
  builder.write_string("  }\n")
  builder.write_string("}\n")
  builder.to_string()
}

///|
fn emit_rule_matcher_function_names(
  rules : Array[RuleSpec],
) -> Array[String] raise {
  let rule_function_names : Array[String] = []
  let owner_rule_ids : Array[String] = []
  for rule in rules {
    let rule_function_name = emit_rule_matcher_function_name(rule.rule_id)
    for index in 0..<rule_function_names.length() {
      if rule_function_names[index] == rule_function_name {
        raise InvalidRule(
          path=rule.rule_id,
          info="rule matcher function name conflict: \{owner_rule_ids[index]} and \{rule.rule_id} both map to \{rule_function_name}",
        )
      }
    }
    rule_function_names.push(rule_function_name)
    owner_rule_ids.push(rule.rule_id)
  }
  rule_function_names
}

///|
fn emit_rule_matcher_function_name(rule_id : String) -> String {
  rule_id.replace_all(old="/", new="_").replace_all(old="-", new="_")
}

///|
fn emit_rule_arm_head(
  pattern_source : String,
  guard_source : String?,
) -> String {
  match guard_source {
    Some(guard_source) => "\{pattern_source} if \{guard_source}"
    None => pattern_source
  }
}

///|
fn ensure_all_metavars_bound(
  rule_id : String,
  pattern_index : Int,
  metavars : Array[String],
  ctx : PatternEmitContext,
) -> Unit raise {
  for meta_name in metavars {
    if find_binding_record(ctx, meta_name) is None {
      raise InvalidRule(
        path=rule_id,
        info="pattern[\{pattern_index}] declares unused metavar \{meta_name}",
      )
    }
  }
}

///|
fn emit_push_source(
  rule : RuleSpec,
  pattern_index : Int,
  ctx : PatternEmitContext,
) -> String {
  let bindings_expr = emit_bindings_expr(ctx)
  "hits.push(MatchHit::{ file, rule_id: \{emit_string_literal(rule.rule_id)}, package_name: \{emit_string_literal(rule.package_name)}, description: \{emit_string_literal(rule.description)}, pattern_index: \{pattern_index}, loc, bindings: \{bindings_expr} })"
}

///|
fn emit_bindings_expr(ctx : PatternEmitContext) -> String {
  if ctx.bindings.is_empty() {
    return "Json::object(Map::of([]))"
  }
  let entries : Array[String] = []
  for binding in ctx.bindings {
    entries.push(
      "\{emit_string_literal(binding.meta_name)}: \{binding.bind_names[0]}",
    )
  }
  let joined_entries = entries.join(", ")
  "{ \{joined_entries} }"
}

///|
fn emit_duplicate_condition(ctx : PatternEmitContext) -> String {
  let conditions : Array[String] = []
  for binding in ctx.bindings {
    if binding.bind_names.length() >= 2 {
      let first = binding.bind_names[0]
      for index in 1..<binding.bind_names.length() {
        conditions.push("\{first} == \{binding.bind_names[index]}")
      }
    }
  }
  conditions.join(" && ")
}

///|
fn emit_pattern_source(
  node : Json,
  ctx : PatternEmitContext,
  root? : Bool = false,
) -> String raise {
  match recognize_metavar(node, ctx) {
    Some(binding_name) => binding_name
    None =>
      match emit_ast_node_source(node, ctx, root~) {
        Some(source) => source
        None =>
          match node {
            Object(map) => {
              let keys : Array[String] = []
              for entry in map.iter() {
                keys.push(entry.0)
              }
              keys.sort()
              let fields : Array[String] = []
              for key in keys {
                let value = map.get(key).unwrap()
                let field_source = emit_pattern_source(value, ctx)
                fields.push("\{emit_string_literal(key)}: \{field_source}")
              }
              if fields.is_empty() {
                "{ .. }"
              } else {
                let joined_fields = fields.join(", ")
                "{ \{joined_fields}, .. }"
              }
            }
            Array(items) =>
              if items.is_empty() {
                "[]"
              } else {
                let item_sources : Array[String] = []
                for item in items {
                  item_sources.push(emit_pattern_source(item, ctx))
                }
                let joined_items = item_sources.join(", ")
                "[\{joined_items}]"
              }
            String(value) => emit_string_literal(value)
            Number(_, ..) | True | False => node.stringify()
            Null => "Null"
          }
      }
  }
}

///|
fn emit_ast_node_source(
  node : Json,
  ctx : PatternEmitContext,
  root? : Bool = false,
) -> String? raise {
  match node {
    Object(map) =>
      if map.length() == 3 {
        match (map.get("kind"), map.get("loc"), map.get("children")) {
          (Some(kind), Some(_), Some(children)) => {
            let kind_source = emit_pattern_source(kind, ctx)
            let children_source = emit_pattern_source(children, ctx)
            if root {
              Some(
                "{ \"kind\": \{kind_source}, \"loc\": loc, \"children\": \{children_source}, .. }",
              )
            } else {
              Some(
                "{ \"kind\": \{kind_source}, \"children\": \{children_source}, .. }",
              )
            }
          }
          _ => None
        }
      } else {
        None
      }
    _ => None
  }
}

///|
fn recognize_metavar(node : Json, ctx : PatternEmitContext) -> String? {
  match node {
    {
      "kind": "Expr::Ident",
      "children": {
        "id": {
          "kind": "Var",
          "children": {
            "name": {
              "kind": "LongIdent::Ident",
              "children": { "value": String(name), .. },
              ..
            },
            ..
          },
          ..
        },
        ..
      },
      ..
    } if ctx.declared_metavars.contains(name) => Some(record_binding(ctx, name))
    { "kind": "Binder", "children": { "name": String(name), .. }, .. } if ctx.declared_metavars.contains(
        name,
      ) => Some(record_binding(ctx, name))
    {
      "kind": "Pattern::Var",
      "children": {
        "value": {
          "kind": "Binder",
          "children": { "name": String(name), .. },
          ..
        },
        ..
      },
      ..
    } if ctx.declared_metavars.contains(name) => Some(record_binding(ctx, name))
    _ => None
  }
}

///|
fn record_binding(ctx : PatternEmitContext, meta_name : String) -> String {
  for index in 0..<ctx.bindings.length() {
    if ctx.bindings[index].meta_name == meta_name {
      let bind_names = ctx.bindings[index].bind_names
      let bind_name = emit_binding_name(
        meta_name,
        bind_names.length() + 1,
        ctx.expose_metavar_names,
      )
      bind_names.push(bind_name)
      return bind_name
    }
  }
  let bind_name = emit_binding_name(meta_name, 1, ctx.expose_metavar_names)
  ctx.bindings.push({ meta_name, bind_names: [bind_name] })
  bind_name
}

///|
fn emit_binding_name(
  meta_name : String,
  occurrence : Int,
  expose_metavar_names : Bool,
) -> String {
  if expose_metavar_names && occurrence == 1 {
    meta_name
  } else {
    "\{sanitize_identifier(meta_name)}_\{occurrence}"
  }
}

///|
fn find_binding_record(
  ctx : PatternEmitContext,
  meta_name : String,
) -> BindingRecord? {
  for binding in ctx.bindings {
    if binding.meta_name == meta_name {
      return Some(binding)
    }
  }
  None
}

///|
fn sanitize_identifier(name : String) -> String {
  let builder = StringBuilder::new(size_hint=name.length() + 5)
  builder.write_string("meta_")
  for index in 0..<name.length() {
    let ch = name.code_unit_at(index).unsafe_to_char()
    if ch == '_' ||
      ch.is_ascii_digit() ||
      ch is ('a'..='z') ||
      ch is ('A'..='Z') {
      builder.write_char(ch)
    } else {
      builder.write_char('_')
    }
  }
  builder.to_string()
}

///|
fn emit_string_literal(value : String) -> String {
  Json::string(value).stringify()
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
test "emit matcher source uses pattern guard and keeps duplicate equality check" {
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
  assert_true(source.contains("} if left != pair => {"))
  assert_true(source.contains("if left == meta_left_2 {"))
  assert_true(source.contains("\"pair\": pair"))
  assert_true(source.contains("\"left\": left"))
}

///|
test "reject guard metavars that conflict with generated locals" {
  let source =
    #|package: moonbit-community/example
    #|description: guarded rule
    #|patterns:
    #|  - shape: |
    #|      foo(file)
    #|    metavars:
    #|      - foo
    #|      - file
    #|    guard: |
    #|      file != foo
  let result = try? parse_rule_source(
    "references/rules/example/test.yaml", "references/rules", source,
  )
  match result {
    Err(InvalidRule(path~, info~)) => {
      inspect(path, content="references/rules/example/test.yaml")
      inspect(
        info,
        content="patterns[0].guard cannot expose metavar file because it conflicts with generated matcher locals",
      )
    }
    _ => fail("expected generated matcher local conflict")
  }
}
