///|
let taint_source_placeholder_name = "__SOURCE__"

///|
priv struct TaintEmitRule {
  rule : @spec.RuleSpec
  taint : @spec.TaintRuleSpec
}

///|
priv enum TaintTargetSlot {
  Receiver
  Argument(Int)
}

///|
priv struct TaintClauseEmitSpec {
  pattern_source : String
  condition_source : String?
  target : TaintTargetSlot?
}

///|
fn emit_taint_bundle_source(rules : Array[@spec.RuleSpec]) -> String raise {
  let builder = StringBuilder::new()
  let taint_rules = collect_taint_rules(rules)
  let function_names = emit_taint_function_names(taint_rules)
  for index in 0..<taint_rules.length() {
    builder.write_string(
      emit_taint_rule_function_source(
        function_names[index],
        taint_rules[index].rule,
        taint_rules[index].taint,
      ),
    )
    builder.write_string("\n")
  }
  builder.write_string(
    emit_taint_rules_table_source(taint_rules, function_names),
  )
  builder.to_string()
}

///|
fn collect_taint_rules(rules : Array[@spec.RuleSpec]) -> Array[TaintEmitRule] {
  let taint_rules : Array[TaintEmitRule] = []
  for rule in rules {
    match rule.definition {
      @spec.RuleDefinitionSpec::Structural(_) => ()
      @spec.RuleDefinitionSpec::Taint(taint) =>
        taint_rules.push({ rule, taint })
    }
  }
  taint_rules
}

///|
fn emit_taint_function_names(
  rules : Array[TaintEmitRule],
) -> Array[String] raise {
  let function_names : Array[String] = []
  let owner_rule_ids : Array[String] = []
  for rule in rules {
    let function_name = emit_taint_custom_function_name(rule.rule.rule_id)
    for index in 0..<function_names.length() {
      if function_names[index] == function_name {
        raise @spec.invalid_rule(
          path=rule.rule.rule_id,
          info="taint custom function name conflict: \{owner_rule_ids[index]} and \{rule.rule.rule_id} both map to \{function_name}",
        )
      }
    }
    function_names.push(function_name)
    owner_rule_ids.push(rule.rule.rule_id)
  }
  function_names
}

///|
fn emit_taint_custom_function_name(rule_id : String) -> String {
  "\{emit_rule_matcher_function_name(rule_id)}__taint_custom"
}

///|
fn emit_taint_rules_table_source(
  rules : Array[TaintEmitRule],
  function_names : Array[String],
) -> String {
  let builder = StringBuilder::new()
  builder.write_string("///|\n")
  builder.write_string(
    "pub let moongrep_taint_rules : Array[BundledTaintRule] = [\n",
  )
  for index in 0..<rules.length() {
    let rule = rules[index].rule
    let sink_ids = emit_taint_sink_ids_source(rules[index].taint)
    builder.write_string("  {\n")
    builder.write_string("    rule_id: \{emit_string_literal(rule.rule_id)},\n")
    builder.write_string(
      "    package_name: \{emit_string_literal(rule.package_name)},\n",
    )
    builder.write_string(
      "    description: \{emit_string_literal(rule.description)},\n",
    )
    builder.write_string("    sink_ids: \{sink_ids},\n")
    builder.write_string("    spec: {\n")
    builder.write_string(
      "      rule_id: \{emit_string_literal(rule.rule_id)},\n",
    )
    builder.write_string("      sources: [],\n")
    builder.write_string("      call_models: [],\n")
    builder.write_string(
      "      unknown_call_policy: @taint.UnknownCallPolicy::NoEffect,\n",
    )
    builder.write_string("      max_fixpoint_iterations: 6,\n")
    builder.write_string(
      "      custom_transfer_call: \{function_names[index]},\n",
    )
    builder.write_string("    },\n")
    builder.write_string("  },\n")
  }
  builder.write_string("]\n")
  builder.to_string()
}

///|
fn emit_taint_sink_ids_source(taint : @spec.TaintRuleSpec) -> String {
  let items : Array[String] = []
  for index in 0..<taint.sinks.length() {
    items.push(emit_string_literal("sink:\{index}"))
  }
  let joined_items = items.join(", ")
  "[\{joined_items}]"
}

///|
fn emit_taint_rule_function_source(
  function_name : String,
  rule : @spec.RuleSpec,
  taint : @spec.TaintRuleSpec,
) -> String raise {
  let builder = StringBuilder::new()
  builder.write_string("///|\n")
  builder.write_string("// bundled taint rule: \{rule.rule_id}\n")
  builder.write_string("#warnings(\"-unused_error_type\")\n")
  builder.write_string(
    "fn \{function_name}(info : @taint.CallInfo) -> @taint.CallTransfer? {\n",
  )
  builder.write_string("  let mut matched = false\n")
  builder.write_string("  let return_taint : @taint.TaintTree = []\n")
  builder.write_string("  let killed_paths : Array[@taint.StoragePath] = []\n")
  builder.write_string("  let findings : Array[@taint.SinkFinding] = []\n")
  builder.write_string(
    emit_taint_clause_group_source(rule.rule_id, "source", taint.sources),
  )
  builder.write_string(
    emit_taint_clause_group_source(rule.rule_id, "sink", taint.sinks),
  )
  builder.write_string(
    emit_taint_clause_group_source(rule.rule_id, "sanitizer", taint.sanitizers),
  )
  builder.write_string("  if matched {\n")
  builder.write_string("    Some({ return_taint, killed_paths, findings })\n")
  builder.write_string("  } else {\n")
  builder.write_string("    None\n")
  builder.write_string("  }\n")
  builder.write_string("}\n")
  builder.to_string()
}

///|
fn emit_taint_clause_group_source(
  rule_id : String,
  clause_kind : String,
  clauses : Array[@spec.RulePatternSpec],
) -> String raise {
  let builder = StringBuilder::new()
  for index in 0..<clauses.length() {
    let clause_context = "taint.\{clause_kind}s[\{index}]"
    let clause_spec = emit_taint_clause_spec(
      rule_id,
      clause_context,
      clauses[index],
      clause_kind != "source",
    )
    builder.write_string("  match info.ast {\n")
    builder.write_string("    // rule: \{rule_id} \{clause_context}\n")
    match clause_spec.condition_source {
      Some(condition_source) =>
        builder.write_string(
          "    \{clause_spec.pattern_source} if \{condition_source} => {\n",
        )
      None => builder.write_string("    \{clause_spec.pattern_source} => {\n")
    }
    builder.write_string("      matched = true\n")
    builder.write_string(
      emit_taint_clause_effect_source(
        rule_id,
        clause_kind,
        index,
        clause_spec.target,
      ),
    )
    builder.write_string("    }\n")
    builder.write_string("    _ => ()\n")
    builder.write_string("  }\n")
  }
  builder.to_string()
}

///|
fn emit_taint_clause_effect_source(
  rule_id : String,
  clause_kind : String,
  clause_index : Int,
  target : TaintTargetSlot?,
) -> String {
  match clause_kind {
    "source" => {
      let source_id = emit_string_literal("source:\{clause_index}")
      "      merge_taint_tree_into(return_taint, fresh_call_return_taint(info, \{emit_string_literal(rule_id)}, \{source_id}))\n"
    }
    "sink" =>
      emit_taint_sink_effect_source(rule_id, clause_index, target.unwrap())
    "sanitizer" => emit_taint_sanitizer_effect_source(target.unwrap())
    _ => panic()
  }
}

///|
fn emit_taint_sink_effect_source(
  rule_id : String,
  clause_index : Int,
  target : TaintTargetSlot,
) -> String {
  let sink_id = emit_string_literal("sink:\{clause_index}")
  let rule_id_source = emit_string_literal(rule_id)
  match target {
    TaintTargetSlot::Receiver =>
      "      match info.receiver_site {\n" +
      "        Some(site) => add_sink_finding_if_tainted(findings, \{rule_id_source}, \{sink_id}, info.loc, site, info.receiver_taint)\n" +
      "        None => ()\n" +
      "      }\n"
    TaintTargetSlot::Argument(index) =>
      "      match info.arguments.get(\{index}) {\n" +
      "        Some(argument) => add_sink_finding_if_tainted(findings, \{rule_id_source}, \{sink_id}, info.loc, argument.site, argument.taint)\n" +
      "        None => ()\n" +
      "      }\n"
  }
}

///|
fn emit_taint_sanitizer_effect_source(target : TaintTargetSlot) -> String {
  match target {
    TaintTargetSlot::Receiver =>
      "      match info.receiver_path {\n" +
      "        Some(path) => add_storage_path_unique(killed_paths, path)\n" +
      "        None => ()\n" +
      "      }\n"
    TaintTargetSlot::Argument(index) =>
      "      match info.arguments.get(\{index}) {\n" +
      "        Some(argument) =>\n" +
      "          match argument.path {\n" +
      "            Some(path) => add_storage_path_unique(killed_paths, path)\n" +
      "            None => ()\n" +
      "          }\n" +
      "        None => ()\n" +
      "      }\n"
  }
}

///|
fn emit_taint_clause_spec(
  rule_id : String,
  clause_context : String,
  clause : @spec.RulePatternSpec,
  require_target : Bool,
) -> TaintClauseEmitSpec raise {
  let ast = @greptools.dump_expr_json_repr(clause.shape)
  ensure_taint_call_shape(rule_id, clause_context, ast)
  let target = detect_taint_target_slot(
    rule_id, clause_context, ast, require_target,
  )
  let ctx = {
    declared_metavars: clause.declared_metavars(),
    special_wildcards: if require_target {
      [taint_source_placeholder_name]
    } else {
      []
    },
    bindings: [],
  }
  let pattern_source = emit_pattern_source(ast, ctx, root=false)
  ensure_all_metavars_bound_in_context(
    rule_id,
    clause_context,
    clause.declared_metavars(),
    ctx,
  )
  {
    pattern_source,
    condition_source: emit_taint_pattern_condition_source(clause, ctx),
    target,
  }
}

///|
fn emit_taint_pattern_condition_source(
  pattern : @spec.RulePatternSpec,
  ctx : PatternEmitContext,
) -> String? {
  let clauses : Array[String] = []
  for condition in emit_identifier_normalization_conditions(pattern, ctx) {
    clauses.push(condition)
  }
  let duplicate_condition = emit_duplicate_condition(pattern, ctx)
  if duplicate_condition != "" {
    clauses.push(duplicate_condition)
  }
  if clauses.is_empty() {
    None
  } else {
    Some(clauses.join(" && "))
  }
}

///|
fn ensure_all_metavars_bound_in_context(
  rule_id : String,
  clause_context : String,
  metavars : Array[String],
  ctx : PatternEmitContext,
) -> Unit raise {
  for meta_name in metavars {
    if find_binding_record(ctx, meta_name) is None {
      raise @spec.invalid_rule(
        path=rule_id,
        info="\{clause_context} declares unused metavar \{meta_name}",
      )
    }
  }
}

///|
fn ensure_taint_call_shape(
  rule_id : String,
  clause_context : String,
  ast : Json,
) -> Unit raise {
  match ast {
    { "kind": "Expr::Apply", .. } | { "kind": "Expr::DotApply", .. } => ()
    _ =>
      raise @spec.invalid_rule(
        path=rule_id,
        info="\{clause_context} shape must be a function or method call expression",
      )
  }
}

///|
fn detect_taint_target_slot(
  rule_id : String,
  clause_context : String,
  ast : Json,
  require_target : Bool,
) -> TaintTargetSlot? raise {
  let placeholder_count = count_special_placeholder(ast)
  if require_target && placeholder_count != 1 {
    raise @spec.invalid_rule(
      path=rule_id,
      info="\{clause_context} must contain exactly one __SOURCE__ target",
    )
  }
  if !require_target && placeholder_count != 0 {
    raise @spec.invalid_rule(
      path=rule_id,
      info="\{clause_context} must not contain __SOURCE__",
    )
  }
  if !require_target {
    return None
  }
  match find_taint_target_slot(ast) {
    Some(target) => Some(target)
    None =>
      raise @spec.invalid_rule(
        path=rule_id,
        info="\{clause_context} must place __SOURCE__ as the entire receiver or argument value",
      )
  }
}

///|
fn find_taint_target_slot(ast : Json) -> TaintTargetSlot? {
  match ast {
    {
      "kind": "Expr::Apply",
      "children": { "args": { "children": Array(args), .. }, .. },
      ..
    } => find_taint_argument_slot(args)
    {
      "kind": "Expr::DotApply",
      "children": {
        "self": self_expr,
        "args": { "children": Array(args), .. },
        ..
      },
      ..
    } =>
      if is_source_placeholder_expr(self_expr) {
        Some(TaintTargetSlot::Receiver)
      } else {
        find_taint_argument_slot(args)
      }
    _ => None
  }
}

///|
fn find_taint_argument_slot(args : Array[Json]) -> TaintTargetSlot? {
  for index in 0..<args.length() {
    match args[index] {
      { "kind": "Argument", "children": { "value": value, .. }, .. } =>
        if is_source_placeholder_expr(value) {
          return Some(TaintTargetSlot::Argument(index))
        }
      _ => ()
    }
  }
  None
}

///|
fn is_source_placeholder_expr(ast : Json) -> Bool {
  match ast {
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
    } => name == taint_source_placeholder_name
    _ => false
  }
}

///|
fn special_placeholder_name(ast : Json) -> String? {
  match ast {
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
    } => Some(name)
    {
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
    } => Some(name)
    { "kind": "Binder", "children": { "name": String(name), .. }, .. } =>
      Some(name)
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
    } => Some(name)
    { "kind": "Label", "children": { "name": String(name), .. }, .. } =>
      Some(name)
    _ => None
  }
}

///|
fn count_special_placeholder(ast : Json) -> Int {
  match special_placeholder_name(ast) {
    Some(name) => if name == taint_source_placeholder_name { 1 } else { 0 }
    None =>
      match ast {
        Object(map) => {
          let mut total = 0
          for _, value in map.iter2() {
            total += count_special_placeholder(value)
          }
          total
        }
        Array(items) => {
          let mut total = 0
          for item in items {
            total += count_special_placeholder(item)
          }
          total
        }
        _ => 0
      }
  }
}
