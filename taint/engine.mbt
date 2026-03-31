// Transfer engine for intra-procedural taint analysis.
//
// The implementation behaves like a small abstract interpreter over parser AST
// JSON. Each expression evaluation produces:
// - a next abstract state
// - a taint tree for the expression's value
// - zero or more sink findings
// - possibly non-local control flow (return / raise / break / continue)
//
// The engine is intentionally intraprocedural. Nested function bodies are
// treated as boundaries; interprocedural behaviour is supplied only through the
// declarative call models plus an optional custom transfer hook.

///|
/// Control-flow exits produced while evaluating an expression.
///
/// Each non-local exit carries the taint of the value being returned, raised,
/// broken with, or continued with so surrounding constructs can merge it.
priv enum FlowExit {
  Normal(TaintTree)
  Return(TaintTree)
  Raise(TaintTree)
  Break(TaintTree)
  Continue(Array[TaintTree])
}

///|
/// One reachable abstract branch after evaluating an expression.
priv struct ExecBranch {
  state : TaintState
  exit : FlowExit
}

///|
/// Full evaluation result for one expression.
priv struct ExecResult {
  branches : Array[ExecBranch]
  findings : Array[SinkFinding]
}

///|
/// One reachable branch after evaluating a condition expression.
///
/// Some conditions such as `x is Some(y)` introduce temporary binders that are
/// only visible in the success path. `restore_*` remembers how to drop those
/// roots once the surrounding branch finishes.
priv struct ConditionBranch {
  state : TaintState
  restore_roots : Array[String]
  restore_baseline : TaintState
}

///|
/// Split condition evaluation into true/false successors plus non-local exits.
priv struct ConditionResult {
  true_branches : Array[ConditionBranch]
  false_branches : Array[ConditionBranch]
  escapes : Array[ExecBranch]
  findings : Array[SinkFinding]
}

///|
/// Top-level entry used by the public API.
///
/// The function:
/// 1. normalizes the AST to `FunctionLikeInfo`
/// 2. seeds initial entry-path taint
/// 3. analyzes the body expression
/// 4. returns only deduplicated sink findings to the caller
fn analyze_function_like_json_impl(
  ast : Json,
  spec : TaintSpec,
) -> AnalysisResult raise {
  guard extract_function_like_info(ast) is Some(info) else {
    raise TaintAnalysisError::UnsupportedFunctionLike(ast)
  }
  let initial_state = seed_state_from_sources(
    info.parameters,
    spec.rule_id,
    spec.sources,
  )
  let result = analyze_expr(info.body, initial_state, spec)
  for branch in result.branches {
    match branch.exit {
      FlowExit::Return(value) => ignore(value)
      _ => ()
    }
  }
  {
    rule_id: spec.rule_id,
    function_name: info.function_name,
    function_loc: info.function_loc,
    findings: dedup_findings(result.findings),
  }
}

///|
/// Seed entry-path taint at function entry.
///
/// Only `SourceModel::EntryPath` participates here; call-return sources are
/// handled later by the call-model lowering layer.
fn seed_state_from_sources(
  parameters : Array[ParameterInfo],
  rule_id : String,
  sources : Array[SourceModel],
) -> TaintState {
  let entries : Array[StateEntry] = []
  for parameter in parameters {
    for source in sources {
      match source {
        SourceModel::EntryPath(target, source_id, note) =>
          if target.root == parameter.name {
            let origin = {
              rule_id,
              origin_id: source_id,
              site: ValueSite::Path(target),
              note: match note {
                Some(note) => Some(note)
                None => Some("parameter \{parameter.name}")
              },
            }
            merge_state_entry(entries, target, [origin])
          } else {
            ()
          }
        _ => ()
      }
    }
  }
  { entries, }
}

///|
fn no_findings(branches : Array[ExecBranch]) -> ExecResult {
  { branches, findings: [] }
}

///|
fn normal_result(state : TaintState, value? : TaintTree = []) -> ExecResult {
  no_findings([{ state, exit: FlowExit::Normal(copy_tree(value)) }])
}

///|
fn merge_findings(
  left : Array[SinkFinding],
  right : Array[SinkFinding],
) -> Array[SinkFinding] {
  let merged : Array[SinkFinding] = []
  for finding in left {
    if !merged.contains(finding) {
      merged.push(finding)
    }
  }
  for finding in right {
    if !merged.contains(finding) {
      merged.push(finding)
    }
  }
  merged
}

///|
fn dedup_findings(findings : Array[SinkFinding]) -> Array[SinkFinding] {
  merge_findings([], findings)
}

///|
fn stamp_origin_rule_id(origin : TaintOrigin, rule_id : String) -> TaintOrigin {
  { rule_id, origin_id: origin.origin_id, site: origin.site, note: origin.note }
}

///|
fn stamp_tree_rule_id(tree : TaintTree, rule_id : String) -> TaintTree {
  let stamped : TaintTree = []
  for entry in tree {
    let origins : Array[TaintOrigin] = []
    for origin in entry.origins {
      origins.push(stamp_origin_rule_id(origin, rule_id))
    }
    stamped.push({ path: copy_segments(entry.path), origins })
  }
  stamped
}

///|
fn stamp_findings_rule_id(
  findings : Array[SinkFinding],
  rule_id : String,
) -> Array[SinkFinding] {
  let stamped : Array[SinkFinding] = []
  for finding in findings {
    let origins : Array[TaintOrigin] = []
    for origin in finding.origins {
      origins.push(stamp_origin_rule_id(origin, rule_id))
    }
    stamped.push({
      rule_id,
      sink_id: finding.sink_id,
      sink_loc: finding.sink_loc,
      sink_site: finding.sink_site,
      origins,
    })
  }
  stamped
}

///|
fn map_branches(
  result : ExecResult,
  f : (ExecBranch) -> Array[ExecBranch],
) -> ExecResult {
  let branches : Array[ExecBranch] = []
  for branch in result.branches {
    for mapped in f(branch) {
      branches.push(mapped)
    }
  }
  { branches, findings: result.findings }
}

///|
/// Main expression transfer dispatcher.
///
/// Every expression-specific helper follows the same contract:
/// - evaluate subexpressions in source order
/// - update abstract state
/// - return value taint for the expression result
/// - preserve non-local control flow via `FlowExit`
fn analyze_expr(
  expr : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  match expr {
    { "kind": "Expr::Ident", .. } =>
      match extract_storage_path(expr) {
        Some(path) => normal_result(state, value=state_read_path(state, path))
        None => normal_result(state)
      }
    { "kind": "Expr::Constant", .. } => normal_result(state)
    {
      "kind": "Expr::Field",
      "children": { "record": record, "accessor": accessor, .. },
      ..
    } => analyze_field_expr(record, accessor, state, spec)
    {
      "kind": "Expr::ArrayGet",
      "children": { "array": array, "index": index, .. },
      ..
    } => analyze_array_get_expr(array, index, state, spec)
    { "kind": "Expr::Record", .. } => analyze_record_expr(expr, state, spec)
    { "kind": "Expr::Array", .. } => analyze_array_expr(expr, state, spec)
    { "kind": "Expr::Tuple", .. } => analyze_tuple_expr(expr, state, spec)
    {
      "kind": "Expr::Let",
      "children": { "pattern": pattern, "expr": rhs, "body": body, .. },
      ..
    } => analyze_let_expr(pattern, rhs, body, state, spec)
    {
      "kind": "Expr::LetMut",
      "children": { "binder": binder, "expr": rhs, "body": body, .. },
      ..
    } => analyze_let_mut_expr(binder, rhs, body, state, spec)
    { "kind": "Expr::Assign", "children": { "var": var_, "expr": rhs, .. }, .. } =>
      analyze_assign_expr(var_, rhs, state, spec)
    {
      "kind": "Expr::Mutate",
      "children": { "record": record, "accessor": accessor, "field": field, .. },
      ..
    } => analyze_mutate_expr(record, accessor, field, state, spec)
    {
      "kind": "Expr::ArraySet",
      "children": { "array": array, "index": index, "value": value, .. },
      ..
    } => analyze_array_set_expr(array, index, value, state, spec)
    {
      "kind": "Expr::Sequence",
      "children": { "exprs": exprs, "last_expr": last_expr, .. },
      ..
    } => analyze_sequence_expr(exprs, last_expr, state, spec)
    {
      "kind": "Expr::If",
      "children": { "cond": cond, "ifso": ifso, "ifnot": ifnot, .. },
      ..
    } => analyze_if_expr(cond, ifso, ifnot, state, spec)
    {
      "kind": "Expr::Match",
      "children": { "expr": subject, "cases": cases, .. },
      ..
    } => analyze_match_like_expr(subject, cases, state, spec)
    {
      "kind": "Expr::Try",
      "children": {
        "body": body,
        "catch": catch_cases,
        "try_else": try_else,
        ..
      },
      ..
    } => analyze_try_expr(body, catch_cases, try_else, state, spec)
    {
      "kind": "Expr::Guard",
      "children": { "cond": cond, "otherwise": otherwise, "body": body, .. },
      ..
    } => analyze_if_expr(cond, body, otherwise, state, spec)
    {
      "kind": "Expr::While",
      "children": {
        "loop_cond": cond,
        "loop_body": body,
        "while_else": while_else,
        ..
      },
      ..
    } => analyze_while_expr(cond, body, while_else, state, spec)
    { "kind": "Expr::For", .. } => analyze_for_expr(expr, state, spec)
    { "kind": "Expr::ForEach", .. } => analyze_foreach_expr(expr, state, spec)
    { "kind": "Expr::Loop", .. } => analyze_loop_expr(expr, state, spec)
    { "kind": "Expr::Apply", .. } => analyze_apply_expr(expr, state, spec)
    { "kind": "Expr::DotApply", .. } =>
      analyze_dot_apply_expr(expr, state, spec)
    { "kind": "Expr::Pipe", .. } => analyze_pipe_expr(expr, state, spec)
    { "kind": "Expr::Return", "children": { "return_value": value, .. }, .. } =>
      rewrap_exit(analyze_expr(value, state, spec), value => {
        FlowExit::Return(value)
      })
    { "kind": "Expr::Raise", "children": { "err_value": value, .. }, .. } =>
      rewrap_exit(analyze_expr(value, state, spec), value => {
        FlowExit::Raise(value)
      })
    { "kind": "Expr::Break", "children": { "arg": value, .. }, .. } =>
      rewrap_exit(analyze_expr(value, state, spec), value => {
        FlowExit::Break(value)
      })
    { "kind": "Expr::Continue", "children": { "args": args, .. }, .. } =>
      analyze_continue_expr(args, state, spec)
    { "kind": "Expr::Function", .. } => normal_result(state)
    {
      "kind": "Expr::LetFn",
      "children": { "name": binder, "body": body, .. },
      ..
    } => analyze_boundary_binding_expr(binder, body, state, spec)
    {
      "kind": "Expr::LetRec",
      "children": { "bindings": bindings, "body": body, .. },
      ..
    } => analyze_boundary_bindings_expr(bindings, body, state, spec)
    {
      "kind": "Expr::LetAnd",
      "children": { "bindings": bindings, "body": body, .. },
      ..
    } => analyze_boundary_bindings_expr(bindings, body, state, spec)
    _ => analyze_unknown_expr(expr, state, spec)
  }
}

///|
/// Convert a normal result into a non-local exit while preserving all other
/// branches unchanged.
fn rewrap_exit(
  result : ExecResult,
  exit_ctor : (TaintTree) -> FlowExit,
) -> ExecResult {
  map_branches(result, branch => {
    match branch.exit {
      FlowExit::Normal(value) =>
        [{ state: branch.state, exit: exit_ctor(value) }]
      _ => [branch]
    }
  })
}

///|
fn restore_scoped_branch(
  branch : ExecBranch,
  scoped_roots : Array[String],
  baseline : TaintState,
) -> ExecBranch {
  if scoped_roots.is_empty() {
    return branch
  }
  {
    state: state_restore_roots(branch.state, scoped_roots, baseline),
    exit: branch.exit,
  }
}

///|
fn restore_scoped_result(
  result : ExecResult,
  scoped_roots : Array[String],
  baseline : TaintState,
) -> ExecResult {
  if scoped_roots.is_empty() {
    return result
  }
  let branches : Array[ExecBranch] = []
  for branch in result.branches {
    branches.push(restore_scoped_branch(branch, scoped_roots, baseline))
  }
  { branches, findings: result.findings }
}

///|
fn copy_strings(items : Array[String]) -> Array[String] {
  let copied : Array[String] = []
  for item in items {
    copied.push(item)
  }
  copied
}

///|
fn merge_root_names(
  left : Array[String],
  right : Array[String],
) -> Array[String] {
  let merged = copy_strings(left)
  for name in right {
    if !merged.contains(name) {
      merged.push(name)
    }
  }
  merged
}

///|
fn condition_bound_roots(cond : Json) -> Array[String] {
  match cond {
    { "kind": "Expr::Is", "children": { "pat": pattern, .. }, .. } =>
      collect_pattern_binder_names(pattern)
    _ => []
  }
}

///|
/// Analyze a condition expression into true/false successors.
///
/// Ordinary boolean expressions stay path-insensitive, so each normal branch
/// feeds both successors. `Expr::Is` is special because a successful match
/// introduces pattern binders that must be scoped to the success path only.
fn analyze_condition_expr(
  cond : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ConditionResult {
  match cond {
    {
      "kind": "Expr::Is",
      "children": { "expr": subject, "pat": pattern, .. },
      ..
    } => analyze_is_condition(subject, pattern, state, spec)
    _ => {
      let result = analyze_expr(cond, state, spec)
      let true_branches : Array[ConditionBranch] = []
      let false_branches : Array[ConditionBranch] = []
      let escapes : Array[ExecBranch] = []
      for branch in result.branches {
        match branch.exit {
          FlowExit::Normal(_) => {
            // v1 does not reason about boolean truthiness, so a normal condition
            // result keeps both successors reachable from the same state.
            true_branches.push({
              state: branch.state,
              restore_roots: [],
              restore_baseline: branch.state,
            })
            false_branches.push({
              state: branch.state,
              restore_roots: [],
              restore_baseline: branch.state,
            })
          }
          _ => escapes.push(branch)
        }
      }
      { true_branches, false_branches, escapes, findings: result.findings }
    }
  }
}

///|
/// `x is pat` first evaluates `x`, then splits into success/failure paths.
///
/// On success, the pattern binders are written into state and remembered so the
/// surrounding control-flow construct can restore outer bindings afterward.
fn analyze_is_condition(
  subject : Json,
  pattern : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ConditionResult {
  let subject_result = analyze_expr(subject, state, spec)
  let true_branches : Array[ConditionBranch] = []
  let false_branches : Array[ConditionBranch] = []
  let escapes : Array[ExecBranch] = []
  let scoped_roots = collect_pattern_binder_names(pattern)
  for branch in subject_result.branches {
    match branch.exit {
      FlowExit::Normal(value) => {
        // Success materializes the pattern binders as ordinary roots so the
        // surrounding body can read them just like locals introduced by `let`.
        true_branches.push({
          state: bind_pattern_to_state(branch.state, pattern, value),
          restore_roots: copy_strings(scoped_roots),
          restore_baseline: branch.state,
        })
        // Failure does not bind anything and keeps the pre-condition state.
        false_branches.push({
          state: branch.state,
          restore_roots: [],
          restore_baseline: branch.state,
        })
      }
      _ => escapes.push(branch)
    }
  }
  { true_branches, false_branches, escapes, findings: subject_result.findings }
}

///|
fn analyze_field_expr(
  record : Json,
  accessor : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let record_result = analyze_expr(record, state, spec)
  let branches : Array[ExecBranch] = []
  for branch in record_result.branches {
    match branch.exit {
      FlowExit::Normal(value) =>
        match accessor_segment(accessor) {
          Some(segment) =>
            branches.push({
              state: branch.state,
              exit: FlowExit::Normal(tree_project(value, [segment])),
            })
          None =>
            branches.push({ state: branch.state, exit: FlowExit::Normal([]) })
        }
      _ => branches.push(branch)
    }
  }
  { branches, findings: record_result.findings }
}

///|
fn analyze_array_get_expr(
  array : Json,
  index : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let array_result = analyze_expr(array, state, spec)
  let branches : Array[ExecBranch] = []
  let findings : Array[SinkFinding] = []
  for finding in array_result.findings {
    findings.push(finding)
  }
  for branch in array_result.branches {
    match branch.exit {
      FlowExit::Normal(value) => {
        let index_result = analyze_expr(index, branch.state, spec)
        for finding in index_result.findings {
          if !findings.contains(finding) {
            findings.push(finding)
          }
        }
        for index_branch in index_result.branches {
          match index_branch.exit {
            FlowExit::Normal(_) =>
              branches.push({
                state: index_branch.state,
                exit: FlowExit::Normal(
                  tree_project(value, [index_segment(index)]),
                ),
              })
            _ => branches.push(index_branch)
          }
        }
      }
      _ => branches.push(branch)
    }
  }
  { branches, findings }
}

///|
fn analyze_record_expr(
  expr : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  match json_child(expr, "fields") {
    Some({ "kind": "Expr::Record::FieldList", "children": Array(fields), .. }) => {
      let mut partials : Array[(TaintState, TaintTree)] = [(state, [])]
      let findings : Array[SinkFinding] = []
      let escapes : Array[ExecBranch] = []
      for field in fields {
        match field {
          {
            "kind": "FieldDef",
            "children": { "label": label, "expr": value_expr, .. },
            ..
          } =>
            match extract_label_name(label) {
              Some(name) => {
                let next_partials : Array[(TaintState, TaintTree)] = []
                for partial in partials {
                  let result = analyze_expr(value_expr, partial.0, spec)
                  for finding in result.findings {
                    if !findings.contains(finding) {
                      findings.push(finding)
                    }
                  }
                  for branch in result.branches {
                    match branch.exit {
                      FlowExit::Normal(value) => {
                        let merged = tree_merge(
                          partial.1,
                          tree_prefix(value, [PathSegment::Field(name)]),
                        )
                        next_partials.push((branch.state, merged))
                      }
                      _ => escapes.push(branch)
                    }
                  }
                }
                partials = next_partials
              }
              None => ()
            }
          _ => ()
        }
      }
      let branches : Array[ExecBranch] = []
      for partial in partials {
        branches.push({ state: partial.0, exit: FlowExit::Normal(partial.1) })
      }
      for branch in escapes {
        branches.push(branch)
      }
      { branches, findings }
    }
    _ => normal_result(state)
  }
}

///|
fn analyze_array_expr(
  expr : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  match json_child(expr, "exprs") {
    Some({ "kind": "Expr::Array::ExprList", "children": Array(items), .. }) => {
      let mut partials : Array[(TaintState, TaintTree)] = [(state, [])]
      let findings : Array[SinkFinding] = []
      let escapes : Array[ExecBranch] = []
      for index in 0..<items.length() {
        let next_partials : Array[(TaintState, TaintTree)] = []
        for partial in partials {
          let result = analyze_expr(items[index], partial.0, spec)
          for finding in result.findings {
            if !findings.contains(finding) {
              findings.push(finding)
            }
          }
          for branch in result.branches {
            match branch.exit {
              FlowExit::Normal(value) => {
                let merged = tree_merge(
                  partial.1,
                  tree_prefix(value, [
                    PathSegment::ConstIndex(index.to_string()),
                  ]),
                )
                next_partials.push((branch.state, merged))
              }
              _ => escapes.push(branch)
            }
          }
        }
        partials = next_partials
      }
      let branches : Array[ExecBranch] = []
      for partial in partials {
        branches.push({ state: partial.0, exit: FlowExit::Normal(partial.1) })
      }
      for branch in escapes {
        branches.push(branch)
      }
      { branches, findings }
    }
    _ => normal_result(state)
  }
}

///|
fn analyze_tuple_expr(
  expr : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  match json_child(expr, "exprs") {
    Some({ "kind": "Expr::Tuple::ExprList", "children": Array(items), .. }) => {
      let mut partials : Array[(TaintState, Array[TaintTree])] = [(state, [])]
      let findings : Array[SinkFinding] = []
      let escapes : Array[ExecBranch] = []
      for item in items {
        let next_partials : Array[(TaintState, Array[TaintTree])] = []
        for partial in partials {
          let result = analyze_expr(item, partial.0, spec)
          for finding in result.findings {
            if !findings.contains(finding) {
              findings.push(finding)
            }
          }
          for branch in result.branches {
            match branch.exit {
              FlowExit::Normal(value) => {
                let values : Array[TaintTree] = []
                for existing in partial.1 {
                  values.push(copy_tree(existing))
                }
                values.push(copy_tree(value))
                next_partials.push((branch.state, values))
              }
              _ => escapes.push(branch)
            }
          }
        }
        partials = next_partials
      }
      let branches : Array[ExecBranch] = []
      for partial in partials {
        branches.push({
          state: partial.0,
          exit: FlowExit::Normal(tuple_tree(partial.1)),
        })
      }
      for branch in escapes {
        branches.push(branch)
      }
      { branches, findings }
    }
    _ => analyze_unknown_expr(expr, state, spec)
  }
}

///|
fn analyze_let_expr(
  pattern : Json,
  rhs : Json,
  body : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let rhs_result = analyze_expr(rhs, state, spec)
  let branches : Array[ExecBranch] = []
  let findings = copy_findings(rhs_result.findings)
  for branch in rhs_result.branches {
    match branch.exit {
      FlowExit::Normal(value) => {
        let body_result = analyze_expr(
          body,
          bind_pattern_to_state(branch.state, pattern, value),
          spec,
        )
        for finding in body_result.findings {
          if !findings.contains(finding) {
            findings.push(finding)
          }
        }
        for body_branch in body_result.branches {
          branches.push(body_branch)
        }
      }
      _ => branches.push(branch)
    }
  }
  { branches, findings }
}

///|
fn analyze_let_mut_expr(
  binder : Json,
  rhs : Json,
  body : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  match binder {
    { "kind": "Binder", "children": { "name": String(name), .. }, .. } => {
      let rhs_result = analyze_expr(rhs, state, spec)
      let branches : Array[ExecBranch] = []
      let findings = copy_findings(rhs_result.findings)
      for branch in rhs_result.branches {
        match branch.exit {
          FlowExit::Normal(value) => {
            let next_state = state_write_path(
              branch.state,
              storage_path(name),
              value,
            )
            let body_result = analyze_expr(body, next_state, spec)
            for finding in body_result.findings {
              if !findings.contains(finding) {
                findings.push(finding)
              }
            }
            for body_branch in body_result.branches {
              branches.push(body_branch)
            }
          }
          _ => branches.push(branch)
        }
      }
      { branches, findings }
    }
    _ => analyze_unknown_expr(rhs, state, spec)
  }
}

///|
fn analyze_assign_expr(
  var_ : Json,
  rhs : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let rhs_result = analyze_expr(rhs, state, spec)
  let branches : Array[ExecBranch] = []
  for branch in rhs_result.branches {
    match branch.exit {
      FlowExit::Normal(value) =>
        match extract_var_name(var_) {
          Some(name) =>
            branches.push({
              state: state_write_path(branch.state, storage_path(name), value),
              exit: FlowExit::Normal([]),
            })
          None =>
            branches.push({ state: branch.state, exit: FlowExit::Normal([]) })
        }
      _ => branches.push(branch)
    }
  }
  { branches, findings: rhs_result.findings }
}

///|
fn analyze_mutate_expr(
  record : Json,
  accessor : Json,
  field : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let record_result = analyze_expr(record, state, spec)
  let findings = copy_findings(record_result.findings)
  let branches : Array[ExecBranch] = []
  for record_branch in record_result.branches {
    match record_branch.exit {
      FlowExit::Normal(_) => {
        let field_result = analyze_expr(field, record_branch.state, spec)
        for finding in field_result.findings {
          if !findings.contains(finding) {
            findings.push(finding)
          }
        }
        for field_branch in field_result.branches {
          match field_branch.exit {
            FlowExit::Normal(value) =>
              match (extract_storage_path(record), accessor_segment(accessor)) {
                (Some(base), Some(segment)) =>
                  branches.push({
                    state: state_write_path(
                      field_branch.state,
                      {
                        root: base.root,
                        segments: append_segments(base.segments, [segment]),
                      },
                      value,
                    ),
                    exit: FlowExit::Normal([]),
                  })
                _ =>
                  branches.push({
                    state: field_branch.state,
                    exit: FlowExit::Normal([]),
                  })
              }
            _ => branches.push(field_branch)
          }
        }
      }
      _ => branches.push(record_branch)
    }
  }
  { branches, findings }
}

///|
fn analyze_array_set_expr(
  array : Json,
  index : Json,
  value_expr : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let array_result = analyze_expr(array, state, spec)
  let findings = copy_findings(array_result.findings)
  let branches : Array[ExecBranch] = []
  for array_branch in array_result.branches {
    match array_branch.exit {
      FlowExit::Normal(_) => {
        let index_result = analyze_expr(index, array_branch.state, spec)
        for finding in index_result.findings {
          if !findings.contains(finding) {
            findings.push(finding)
          }
        }
        for index_branch in index_result.branches {
          match index_branch.exit {
            FlowExit::Normal(_) => {
              let value_result = analyze_expr(
                value_expr,
                index_branch.state,
                spec,
              )
              for finding in value_result.findings {
                if !findings.contains(finding) {
                  findings.push(finding)
                }
              }
              for value_branch in value_result.branches {
                match value_branch.exit {
                  FlowExit::Normal(value) =>
                    match extract_storage_path(array) {
                      Some(base) =>
                        branches.push({
                          state: state_write_path(
                            value_branch.state,
                            {
                              root: base.root,
                              segments: append_segments(base.segments, [
                                index_segment(index),
                              ]),
                            },
                            value,
                          ),
                          exit: FlowExit::Normal([]),
                        })
                      None =>
                        branches.push({
                          state: value_branch.state,
                          exit: FlowExit::Normal([]),
                        })
                    }
                  _ => branches.push(value_branch)
                }
              }
            }
            _ => branches.push(index_branch)
          }
        }
      }
      _ => branches.push(array_branch)
    }
  }
  { branches, findings }
}

///|
fn analyze_sequence_expr(
  exprs_ast : Json,
  last_expr : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let mut current : Array[ExecBranch] = [{ state, exit: FlowExit::Normal([]) }]
  let findings : Array[SinkFinding] = []
  let exprs = match exprs_ast {
    { "children": Array(items), .. } => items
    _ => []
  }
  for item in exprs {
    let next_current : Array[ExecBranch] = []
    for branch in current {
      match branch.exit {
        FlowExit::Normal(_) => {
          let result = analyze_expr(item, branch.state, spec)
          for finding in result.findings {
            if !findings.contains(finding) {
              findings.push(finding)
            }
          }
          for item_branch in result.branches {
            next_current.push(item_branch)
          }
        }
        _ => next_current.push(branch)
      }
    }
    current = next_current
  }
  let branches : Array[ExecBranch] = []
  for branch in current {
    match branch.exit {
      FlowExit::Normal(_) => {
        let result = analyze_expr(last_expr, branch.state, spec)
        for finding in result.findings {
          if !findings.contains(finding) {
            findings.push(finding)
          }
        }
        for last_branch in result.branches {
          branches.push(last_branch)
        }
      }
      _ => branches.push(branch)
    }
  }
  { branches, findings }
}

///|
/// Conditional branching evaluates the condition, then routes true/false paths
/// separately so `is`-pattern binders stay scoped to the success branch only.
fn analyze_if_expr(
  cond : Json,
  ifso : Json,
  ifnot : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let cond_result = analyze_condition_expr(cond, state, spec)
  let branches : Array[ExecBranch] = []
  let findings = copy_findings(cond_result.findings)
  for cond_branch in cond_result.true_branches {
    // The then-branch may see temporary binders from `is`, but any shadowed
    // outer roots must be restored once control leaves the branch.
    let ifso_result = restore_scoped_result(
      analyze_expr(ifso, cond_branch.state, spec),
      cond_branch.restore_roots,
      cond_branch.restore_baseline,
    )
    for finding in ifso_result.findings {
      if !findings.contains(finding) {
        findings.push(finding)
      }
    }
    for ifso_branch in ifso_result.branches {
      branches.push(ifso_branch)
    }
  }
  for cond_branch in cond_result.false_branches {
    // False-branch execution follows the same restoration rule so condition-only
    // binders never leak beyond the `if`.
    let ifnot_result = restore_scoped_result(
      analyze_expr(ifnot, cond_branch.state, spec),
      cond_branch.restore_roots,
      cond_branch.restore_baseline,
    )
    for finding in ifnot_result.findings {
      if !findings.contains(finding) {
        findings.push(finding)
      }
    }
    for ifnot_branch in ifnot_result.branches {
      branches.push(ifnot_branch)
    }
  }
  for escape in cond_result.escapes {
    branches.push(escape)
  }
  { branches, findings }
}

///|
/// Shared implementation for `match`-style branching constructs.
fn analyze_match_like_expr(
  subject : Json,
  cases : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let subject_result = analyze_expr(subject, state, spec)
  let branches : Array[ExecBranch] = []
  let findings = copy_findings(subject_result.findings)
  let case_items = match cases {
    { "children": Array(items), .. } => items
    _ => []
  }
  for branch in subject_result.branches {
    match branch.exit {
      FlowExit::Normal(value) =>
        for case_ in case_items {
          let case_result = analyze_case(case_, branch.state, value, spec)
          for finding in case_result.findings {
            if !findings.contains(finding) {
              findings.push(finding)
            }
          }
          for case_branch in case_result.branches {
            branches.push(case_branch)
          }
        }
      _ => branches.push(branch)
    }
  }
  { branches, findings }
}

///|
/// Analyze one `match` case with proper pattern scoping.
///
/// Guard failures keep execution alive and restore the outer bindings so later
/// cases still see the pre-match state.
fn analyze_case(
  case_ : Json,
  state : TaintState,
  value : TaintTree,
  spec : TaintSpec,
) -> ExecResult {
  match case_ {
    {
      "kind": "Case",
      "children": { "pattern": pattern, "guard": guard_, "body": body, .. },
      ..
    } => {
      let pattern_roots = collect_pattern_binder_names(pattern)
      let bound_state = bind_pattern_to_state(state, pattern, value)
      match guard_ {
        Null =>
          restore_scoped_result(
            analyze_expr(body, bound_state, spec),
            pattern_roots,
            state,
          )
        _ => {
          // A guard can introduce extra binders via `is`, so restore both the
          // arm pattern names and any temporary guard-only names afterward.
          let scoped_roots = merge_root_names(
            pattern_roots,
            condition_bound_roots(guard_),
          )
          let guard_result = analyze_condition_expr(guard_, bound_state, spec)
          let findings = copy_findings(guard_result.findings)
          let branches : Array[ExecBranch] = []
          for guard_branch in guard_result.true_branches {
            let body_result = restore_scoped_result(
              analyze_expr(body, guard_branch.state, spec),
              scoped_roots,
              state,
            )
            for finding in body_result.findings {
              if !findings.contains(finding) {
                findings.push(finding)
              }
            }
            for body_branch in body_result.branches {
              branches.push(body_branch)
            }
          }
          for guard_branch in guard_result.false_branches {
            // Guard failure falls through to later cases from the outer state,
            // not from the arm's temporarily-bound scope.
            branches.push({
              state: state_restore_roots(
                guard_branch.state,
                scoped_roots,
                state,
              ),
              exit: FlowExit::Normal([]),
            })
          }
          for escape in guard_result.escapes {
            branches.push(restore_scoped_branch(escape, scoped_roots, state))
          }
          { branches, findings }
        }
      }
    }
    _ => normal_result(state)
  }
}

///|
/// Analyze one `catch` case.
///
/// A failing guard preserves the original raised value so later catch cases, or
/// an outer `try`, can still observe it.
fn analyze_catch_case(
  case_ : Json,
  state : TaintState,
  value : TaintTree,
  spec : TaintSpec,
) -> ExecResult {
  match case_ {
    {
      "kind": "Case",
      "children": { "pattern": pattern, "guard": guard_, "body": body, .. },
      ..
    } => {
      let pattern_roots = collect_pattern_binder_names(pattern)
      let bound_state = bind_pattern_to_state(state, pattern, value)
      match guard_ {
        Null =>
          restore_scoped_result(
            analyze_expr(body, bound_state, spec),
            pattern_roots,
            state,
          )
        _ => {
          // Catch guards share the same scoping rules as match guards.
          let scoped_roots = merge_root_names(
            pattern_roots,
            condition_bound_roots(guard_),
          )
          let guard_result = analyze_condition_expr(guard_, bound_state, spec)
          let findings = copy_findings(guard_result.findings)
          let branches : Array[ExecBranch] = []
          for guard_branch in guard_result.true_branches {
            let body_result = restore_scoped_result(
              analyze_expr(body, guard_branch.state, spec),
              scoped_roots,
              state,
            )
            for finding in body_result.findings {
              if !findings.contains(finding) {
                findings.push(finding)
              }
            }
            for body_branch in body_result.branches {
              branches.push(body_branch)
            }
          }
          for guard_branch in guard_result.false_branches {
            // A failed catch guard must re-raise the original value so later
            // catch cases, or an outer `try`, still see the same exception.
            branches.push({
              state: state_restore_roots(
                guard_branch.state,
                scoped_roots,
                state,
              ),
              exit: FlowExit::Raise(copy_tree(value)),
            })
          }
          for escape in guard_result.escapes {
            branches.push(restore_scoped_branch(escape, scoped_roots, state))
          }
          { branches, findings }
        }
      }
    }
    _ => { branches: [], findings: [] }
  }
}

///|
/// `try` analyzes the body first and then dispatches raised branches to catch
/// cases. Non-raised normal branches may continue into `try_else`.
fn analyze_try_expr(
  body : Json,
  catch_cases : Json,
  try_else : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let body_result = analyze_expr(body, state, spec)
  let findings = copy_findings(body_result.findings)
  let branches : Array[ExecBranch] = []
  let cases = match catch_cases {
    { "children": Array(items), .. } => items
    _ => []
  }
  for branch in body_result.branches {
    match branch.exit {
      FlowExit::Raise(value) => {
        branches.push({
          state: branch.state,
          exit: FlowExit::Raise(copy_tree(value)),
        })
        for case_ in cases {
          let case_result = analyze_catch_case(case_, branch.state, value, spec)
          for finding in case_result.findings {
            if !findings.contains(finding) {
              findings.push(finding)
            }
          }
          for case_branch in case_result.branches {
            branches.push(case_branch)
          }
        }
      }
      FlowExit::Normal(value) =>
        match try_else {
          Null =>
            branches.push({ state: branch.state, exit: FlowExit::Normal(value) })
          _ => {
            let else_result = analyze_expr(try_else, branch.state, spec)
            for finding in else_result.findings {
              if !findings.contains(finding) {
                findings.push(finding)
              }
            }
            for else_branch in else_result.branches {
              branches.push(else_branch)
            }
          }
        }
      _ => branches.push(branch)
    }
  }
  { branches, findings }
}

///|
/// Bounded fixpoint for `while`.
///
/// `head_state` is the abstract state at the loop head. Each iteration runs the
/// condition and body, collects backedges, then joins them with the original
/// entry state until convergence or the user-supplied iteration cap.
fn analyze_while_expr(
  cond : Json,
  body : Json,
  while_else : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let mut head_state = state
  let findings : Array[SinkFinding] = []
  let exit_states : Array[TaintState] = []
  let exit_value : TaintTree = []
  let escapes : Array[ExecBranch] = []
  for _ in 0..<spec.max_fixpoint_iterations {
    let cond_result = analyze_condition_expr(cond, head_state, spec)
    for finding in cond_result.findings {
      if !findings.contains(finding) {
        findings.push(finding)
      }
    }
    let backedge_states : Array[TaintState] = []
    for cond_branch in cond_result.false_branches {
      // Exiting the loop through a false condition should discard any temporary
      // binders introduced while checking that condition.
      exit_states.push(
        state_restore_roots(
          cond_branch.state,
          cond_branch.restore_roots,
          cond_branch.restore_baseline,
        ),
      )
    }
    for cond_branch in cond_result.true_branches {
      // The loop body sees success-path binders, but the next iteration and the
      // post-loop state must go back to the pre-condition root layout.
      let body_result = restore_scoped_result(
        analyze_expr(body, cond_branch.state, spec),
        cond_branch.restore_roots,
        cond_branch.restore_baseline,
      )
      for finding in body_result.findings {
        if !findings.contains(finding) {
          findings.push(finding)
        }
      }
      for body_branch in body_result.branches {
        match body_branch.exit {
          FlowExit::Normal(_) | FlowExit::Continue(_) =>
            backedge_states.push(body_branch.state)
          FlowExit::Break(value) => {
            exit_states.push(body_branch.state)
            for entry in value {
              merge_relative_entry(exit_value, entry.path, entry.origins)
            }
          }
          _ => escapes.push(body_branch)
        }
      }
    }
    for escape in cond_result.escapes {
      escapes.push(escape)
    }
    // Joining with the original entry state keeps the zero-iteration path
    // reachable even when the condition/body only adds taint.
    let next_head = state_merge(state, state_merge_all(backedge_states))
    if state_equiv(next_head, head_state) {
      head_state = next_head
      break
    }
    head_state = next_head
  }
  let final_exit_state = state_merge_all(exit_states)
  let branches : Array[ExecBranch] = []
  match while_else {
    Null =>
      branches.push({
        state: final_exit_state,
        exit: FlowExit::Normal(exit_value),
      })
    _ => {
      let else_result = analyze_expr(while_else, final_exit_state, spec)
      for finding in else_result.findings {
        if !findings.contains(finding) {
          findings.push(finding)
        }
      }
      for branch in else_result.branches {
        branches.push(branch)
      }
    }
  }
  for escape in escapes {
    branches.push(escape)
  }
  { branches, findings }
}

///|
/// Entry for C-style `for`, split so binder initialization can reuse normal
/// expression evaluation before entering the fixpoint loop.
fn analyze_for_expr(
  expr : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let binders = match json_child(expr, "binders") {
    Some(binders) => binders
    None => return normal_result(state)
  }
  let condition = match json_child(expr, "condition") {
    Some(condition) => condition
    None => return normal_result(state)
  }
  let continue_block = match json_child(expr, "continue_block") {
    Some(continue_block) => continue_block
    None => return normal_result(state)
  }
  let body = match json_child(expr, "body") {
    Some(body) => body
    None => return normal_result(state)
  }
  let for_else = match json_child(expr, "for_else") {
    Some(for_else) => for_else
    None => null
  }
  let init_result = analyze_for_binders(binders, state, spec)
  let findings = copy_findings(init_result.findings)
  let branches : Array[ExecBranch] = []
  for init_branch in init_result.branches {
    match init_branch.exit {
      FlowExit::Normal(_) => {
        let loop_result = analyze_for_loop_from_state(
          condition,
          continue_block,
          body,
          for_else,
          init_branch.state,
          spec,
        )
        for finding in loop_result.findings {
          if !findings.contains(finding) {
            findings.push(finding)
          }
        }
        for branch in loop_result.branches {
          branches.push(branch)
        }
      }
      _ => branches.push(init_branch)
    }
  }
  { branches, findings }
}

///|
/// Evaluate `for` binders left-to-right and write each bound name into state.
fn analyze_for_binders(
  binders : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  match binders {
    { "children": Array(items), .. } => {
      let mut current : Array[ExecBranch] = [
        { state, exit: FlowExit::Normal([]) },
      ]
      let findings : Array[SinkFinding] = []
      for item in items {
        let next_current : Array[ExecBranch] = []
        for branch in current {
          match branch.exit {
            FlowExit::Normal(_) =>
              match item {
                {
                  "kind": "For::Binding",
                  "children": { "binder": binder, "expr": value_expr, .. },
                  ..
                } => {
                  let result = analyze_expr(value_expr, branch.state, spec)
                  for finding in result.findings {
                    if !findings.contains(finding) {
                      findings.push(finding)
                    }
                  }
                  for result_branch in result.branches {
                    match result_branch.exit {
                      FlowExit::Normal(value) =>
                        match binder {
                          {
                            "kind": "Binder",
                            "children": { "name": String(name), .. },
                            ..
                          } =>
                            next_current.push({
                              state: state_write_path(
                                result_branch.state,
                                storage_path(name),
                                value,
                              ),
                              exit: FlowExit::Normal([]),
                            })
                          _ => next_current.push(result_branch)
                        }
                      _ => next_current.push(result_branch)
                    }
                  }
                }
                _ => next_current.push(branch)
              }
            _ => next_current.push(branch)
          }
        }
        current = next_current
      }
      { branches: current, findings }
    }
    _ => normal_result(state)
  }
}

///|
fn analyze_for_continue_bindings(
  cont_bindings : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  analyze_for_binders(cont_bindings, state, spec)
}

///|
/// Bounded fixpoint for C-style `for`.
///
/// Continue-block bindings are evaluated on backedges so updates such as
/// `i = i + 1` become visible at the next loop head.
fn analyze_for_loop_from_state(
  condition : Json,
  continue_block : Json,
  body : Json,
  for_else : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let mut head_state = state
  let findings : Array[SinkFinding] = []
  let exit_states : Array[TaintState] = []
  let escapes : Array[ExecBranch] = []
  for _ in 0..<spec.max_fixpoint_iterations {
    let cond_result = analyze_expr(condition, head_state, spec)
    for finding in cond_result.findings {
      if !findings.contains(finding) {
        findings.push(finding)
      }
    }
    let backedge_states : Array[TaintState] = []
    for cond_branch in cond_result.branches {
      match cond_branch.exit {
        FlowExit::Normal(_) => {
          exit_states.push(cond_branch.state)
          let body_result = analyze_expr(body, cond_branch.state, spec)
          for finding in body_result.findings {
            if !findings.contains(finding) {
              findings.push(finding)
            }
          }
          for body_branch in body_result.branches {
            match body_branch.exit {
              FlowExit::Normal(_) | FlowExit::Continue(_) => {
                let cont_result = analyze_for_continue_bindings(
                  continue_block,
                  body_branch.state,
                  spec,
                )
                for finding in cont_result.findings {
                  if !findings.contains(finding) {
                    findings.push(finding)
                  }
                }
                for cont_branch in cont_result.branches {
                  match cont_branch.exit {
                    FlowExit::Normal(_) =>
                      backedge_states.push(cont_branch.state)
                    _ => escapes.push(cont_branch)
                  }
                }
              }
              FlowExit::Break(_) => exit_states.push(body_branch.state)
              _ => escapes.push(body_branch)
            }
          }
        }
        _ => escapes.push(cond_branch)
      }
    }
    let next_head = state_merge(state, state_merge_all(backedge_states))
    if state_equiv(next_head, head_state) {
      head_state = next_head
      break
    }
    head_state = next_head
  }
  let final_exit_state = state_merge_all(exit_states)
  let branches : Array[ExecBranch] = []
  match for_else {
    Null =>
      branches.push({ state: final_exit_state, exit: FlowExit::Normal([]) })
    _ => {
      let else_result = analyze_expr(for_else, final_exit_state, spec)
      for finding in else_result.findings {
        if !findings.contains(finding) {
          findings.push(finding)
        }
      }
      for branch in else_result.branches {
        branches.push(branch)
      }
    }
  }
  for escape in escapes {
    branches.push(escape)
  }
  { branches, findings }
}

///|
/// `foreach` first evaluates the collection, then projects an element taint
/// view and runs a bounded fixpoint over the loop body.
fn analyze_foreach_expr(
  expr : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let binders = match json_child(expr, "binders") {
    Some(binders) => binders
    None => return normal_result(state)
  }
  let collection = match json_child(expr, "expr") {
    Some(collection) => collection
    None => return normal_result(state)
  }
  let body = match json_child(expr, "body") {
    Some(body) => body
    None => return normal_result(state)
  }
  let else_block = match json_child(expr, "else_block") {
    Some(else_block) => else_block
    None => null
  }
  let collection_result = analyze_expr(collection, state, spec)
  let findings = copy_findings(collection_result.findings)
  let branches : Array[ExecBranch] = []
  for collection_branch in collection_result.branches {
    match collection_branch.exit {
      FlowExit::Normal(value) => {
        let element_value = collection_element_tree(value)
        let loop_result = analyze_foreach_loop_from_state(
          binders,
          element_value,
          body,
          else_block,
          collection_branch.state,
          spec,
        )
        for finding in loop_result.findings {
          if !findings.contains(finding) {
            findings.push(finding)
          }
        }
        for branch in loop_result.branches {
          branches.push(branch)
        }
      }
      _ => branches.push(collection_branch)
    }
  }
  { branches, findings }
}

///|
/// Bind the `foreach` binder pattern to the abstract element value.
fn bind_foreach_binders(
  binders : Json,
  state : TaintState,
  element_value : TaintTree,
) -> TaintState {
  match binders {
    { "children": Array(items), .. } => {
      let names : Array[String] = []
      for item in items {
        match item {
          { "kind": "Binder", "children": { "name": String(name), .. }, .. } =>
            if !names.contains(name) {
              names.push(name)
            }
          _ => ()
        }
      }
      let mut next = state_kill_roots(state, names)
      for index in 0..<items.length() {
        match items[index] {
          { "kind": "Binder", "children": { "name": String(name), .. }, .. } => {
            let value = if items.length() == 1 {
              element_value
            } else {
              let projected = tree_project(element_value, [
                PathSegment::TupleIndex(index),
              ])
              if projected.is_empty() {
                element_value
              } else {
                projected
              }
            }
            next = state_write_path(next, storage_path(name), value)
          }
          _ => ()
        }
      }
      next
    }
    _ => state
  }
}

///|
/// Bounded fixpoint for `foreach`.
fn analyze_foreach_loop_from_state(
  binders : Json,
  element_value : TaintTree,
  body : Json,
  else_block : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let mut head_state = state
  let findings : Array[SinkFinding] = []
  let exit_states : Array[TaintState] = [state]
  let escapes : Array[ExecBranch] = []
  for _ in 0..<spec.max_fixpoint_iterations {
    let body_state = bind_foreach_binders(binders, head_state, element_value)
    let body_result = analyze_expr(body, body_state, spec)
    for finding in body_result.findings {
      if !findings.contains(finding) {
        findings.push(finding)
      }
    }
    let backedge_states : Array[TaintState] = []
    for branch in body_result.branches {
      match branch.exit {
        FlowExit::Normal(_) | FlowExit::Continue(_) =>
          backedge_states.push(branch.state)
        FlowExit::Break(_) => exit_states.push(branch.state)
        _ => escapes.push(branch)
      }
    }
    let next_head = state_merge(state, state_merge_all(backedge_states))
    if state_equiv(next_head, head_state) {
      head_state = next_head
      break
    }
    head_state = next_head
  }
  let final_exit_state = state_merge_all(exit_states)
  let branches : Array[ExecBranch] = []
  match else_block {
    Null =>
      branches.push({ state: final_exit_state, exit: FlowExit::Normal([]) })
    _ => {
      let else_result = analyze_expr(else_block, final_exit_state, spec)
      for finding in else_result.findings {
        if !findings.contains(finding) {
          findings.push(finding)
        }
      }
      for branch in else_result.branches {
        branches.push(branch)
      }
    }
  }
  for escape in escapes {
    branches.push(escape)
  }
  { branches, findings }
}

///|
/// Entry for `loop` / `continue` constructs that carry explicit values through
/// the backedge.
fn analyze_loop_expr(
  expr : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let arg = match json_child(expr, "arg") {
    Some(arg) => arg
    None => return normal_result(state)
  }
  let cases = match json_child(expr, "body") {
    Some(cases) => cases
    None => return normal_result(state)
  }
  let arg_result = analyze_expr(arg, state, spec)
  let findings = copy_findings(arg_result.findings)
  let branches : Array[ExecBranch] = []
  for arg_branch in arg_result.branches {
    match arg_branch.exit {
      FlowExit::Normal(value) => {
        let loop_result = analyze_loop_from_state(
          cases,
          arg_branch.state,
          value,
          spec,
        )
        for finding in loop_result.findings {
          if !findings.contains(finding) {
            findings.push(finding)
          }
        }
        for branch in loop_result.branches {
          branches.push(branch)
        }
      }
      _ => branches.push(arg_branch)
    }
  }
  { branches, findings }
}

///|
/// Fixpoint for `loop`.
///
/// Unlike `while` and `for`, both the state and the loop-carried value must
/// converge, so the loop head tracks two evolving components.
fn analyze_loop_from_state(
  cases : Json,
  state : TaintState,
  arg_value : TaintTree,
  spec : TaintSpec,
) -> ExecResult {
  let case_items = match cases {
    { "children": Array(items), .. } => items
    _ => []
  }
  let mut head_state = state
  let mut head_value = copy_tree(arg_value)
  let findings : Array[SinkFinding] = []
  let exit_states : Array[TaintState] = []
  let exit_value : TaintTree = []
  let escapes : Array[ExecBranch] = []
  for _ in 0..<spec.max_fixpoint_iterations {
    let backedge_states : Array[TaintState] = []
    let backedge_value : TaintTree = []
    for case_ in case_items {
      let case_result = analyze_case(case_, head_state, head_value, spec)
      for finding in case_result.findings {
        if !findings.contains(finding) {
          findings.push(finding)
        }
      }
      for branch in case_result.branches {
        match branch.exit {
          FlowExit::Normal(value) | FlowExit::Break(value) => {
            exit_states.push(branch.state)
            for entry in value {
              merge_relative_entry(exit_value, entry.path, entry.origins)
            }
          }
          FlowExit::Continue(values) => {
            backedge_states.push(branch.state)
            let next_value = if values.length() == 1 {
              values[0]
            } else {
              tuple_tree(values)
            }
            for entry in next_value {
              merge_relative_entry(backedge_value, entry.path, entry.origins)
            }
          }
          _ => escapes.push(branch)
        }
      }
    }
    let next_state = state_merge(state, state_merge_all(backedge_states))
    let next_value = tree_merge(arg_value, backedge_value)
    if state_equiv(next_state, head_state) && next_value == head_value {
      head_state = next_state
      head_value = next_value
      break
    }
    head_state = next_state
    head_value = next_value
  }
  let branches : Array[ExecBranch] = [
    { state: state_merge_all(exit_states), exit: FlowExit::Normal(exit_value) },
  ]
  for escape in escapes {
    branches.push(escape)
  }
  { branches, findings }
}

///|
/// Entry for a plain function call expression.
fn analyze_apply_expr(
  expr : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  match expr {
    {
      "kind": "Expr::Apply",
      "loc": loc,
      "children": { "func": func, "args": args, .. },
      ..
    } =>
      analyze_call(
        {
          kind: CallKind::Apply,
          ast: expr,
          loc,
          callee_name: extract_call_target_name(func),
          receiver_path: None,
          receiver_site: None,
          receiver_taint: [],
          arguments: [],
        },
        Some(func),
        None,
        args,
        state,
        spec,
      )
    _ => normal_result(state)
  }
}

///|
/// Entry for method-call syntax where the receiver is evaluated separately from
/// explicit arguments.
fn analyze_dot_apply_expr(
  expr : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  match expr {
    {
      "kind": "Expr::DotApply",
      "loc": loc,
      "children": {
        "self": self_expr,
        "method_name": method_name,
        "args": args,
        ..
      },
      ..
    } => {
      let callee_name = extract_label_name(method_name)
      analyze_call(
        {
          kind: CallKind::DotApply,
          ast: expr,
          loc,
          callee_name,
          receiver_path: extract_storage_path(self_expr),
          receiver_site: Some(value_site_for_expr(self_expr)),
          receiver_taint: [],
          arguments: [],
        },
        None,
        Some(self_expr),
        args,
        state,
        spec,
      )
    }
    _ => normal_result(state)
  }
}

///|
/// Entry for pipe syntax.
///
/// The left-hand side is turned into synthetic argument 0 before the right-hand
/// call form is analyzed.
fn analyze_pipe_expr(
  expr : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  match expr {
    {
      "kind": "Expr::Pipe",
      "loc": loc,
      "children": { "lhs": lhs, "rhs": rhs, .. },
      ..
    } => {
      let lhs_result = analyze_expr(lhs, state, spec)
      let findings = copy_findings(lhs_result.findings)
      let branches : Array[ExecBranch] = []
      for lhs_branch in lhs_result.branches {
        match lhs_branch.exit {
          FlowExit::Normal(lhs_value) => {
            let seed_argument : CallArgument = {
              index: 0,
              label: None,
              expr: lhs,
              loc: json_loc(lhs),
              path: extract_storage_path(lhs),
              site: value_site_for_expr(lhs),
              taint: lhs_value,
            }
            let result = match rhs {
              {
                "kind": "Expr::Apply",
                "children": { "func": func, "args": args, .. },
                ..
              } =>
                analyze_call(
                  {
                    kind: CallKind::Pipe,
                    ast: expr,
                    loc,
                    callee_name: extract_call_target_name(func),
                    receiver_path: None,
                    receiver_site: None,
                    receiver_taint: [],
                    arguments: [seed_argument],
                  },
                  Some(func),
                  None,
                  args,
                  lhs_branch.state,
                  spec,
                )
              {
                "kind": "Expr::DotApply",
                "children": {
                  "self": self_expr,
                  "method_name": method_name,
                  "args": args,
                  ..
                },
                ..
              } =>
                analyze_call(
                  {
                    kind: CallKind::Pipe,
                    ast: expr,
                    loc,
                    callee_name: extract_label_name(method_name),
                    receiver_path: extract_storage_path(self_expr),
                    receiver_site: Some(value_site_for_expr(self_expr)),
                    receiver_taint: [],
                    arguments: [seed_argument],
                  },
                  None,
                  Some(self_expr),
                  args,
                  lhs_branch.state,
                  spec,
                )
              _ =>
                analyze_call(
                  {
                    kind: CallKind::Pipe,
                    ast: expr,
                    loc,
                    callee_name: extract_call_target_name(rhs),
                    receiver_path: None,
                    receiver_site: None,
                    receiver_taint: [],
                    arguments: [seed_argument],
                  },
                  Some(rhs),
                  None,
                  null,
                  lhs_branch.state,
                  spec,
                )
            }
            for finding in result.findings {
              if !findings.contains(finding) {
                findings.push(finding)
              }
            }
            for result_branch in result.branches {
              branches.push(result_branch)
            }
          }
          _ => branches.push(lhs_branch)
        }
      }
      { branches, findings }
    }
    _ => normal_result(state)
  }
}

///|
/// Best-effort callee-name extraction used by call-model matching.
fn extract_call_target_name(ast : Json) -> String? {
  match ast {
    { "kind": "Expr::Ident", .. } => extract_ident_name(ast)
    { "kind": "Expr::Field", "children": { "accessor": accessor, .. }, .. } =>
      match accessor_segment(accessor) {
        Some(PathSegment::Field(name)) => Some(name)
        Some(PathSegment::TupleIndex(index)) => Some(index.to_string())
        _ => None
      }
    _ => None
  }
}

///|
/// Evaluate a call in source order and build the `CallInfo` passed to the
/// declarative/custom call-model layer.
///
/// The order is:
/// 1. callee expression
/// 2. receiver expression, when present
/// 3. each explicit argument from left to right
/// 4. transfer application
///
/// Escaping control-flow from any subexpression is preserved and bypasses the
/// call summary step.
fn analyze_call(
  seed_info : CallInfo,
  callee_expr : Json?,
  receiver_expr : Json?,
  args_ast : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let findings : Array[SinkFinding] = []
  let mut partials : Array[CallInfo] = [seed_info]
  let mut states : Array[TaintState] = [state]
  let escapes : Array[ExecBranch] = []
  match callee_expr {
    Some(callee) => {
      let next_infos : Array[CallInfo] = []
      let next_states : Array[TaintState] = []
      for index in 0..<partials.length() {
        let result = analyze_expr(callee, states[index], spec)
        for finding in result.findings {
          if !findings.contains(finding) {
            findings.push(finding)
          }
        }
        for branch in result.branches {
          match branch.exit {
            FlowExit::Normal(_) => {
              next_infos.push(partials[index])
              next_states.push(branch.state)
            }
            _ => escapes.push(branch)
          }
        }
      }
      partials = next_infos
      states = next_states
    }
    None => ()
  }
  match receiver_expr {
    Some(receiver) => {
      let next_infos : Array[CallInfo] = []
      let next_states : Array[TaintState] = []
      for index in 0..<partials.length() {
        let result = analyze_expr(receiver, states[index], spec)
        for finding in result.findings {
          if !findings.contains(finding) {
            findings.push(finding)
          }
        }
        for branch in result.branches {
          match branch.exit {
            FlowExit::Normal(value) => {
              next_infos.push({
                kind: partials[index].kind,
                ast: partials[index].ast,
                loc: partials[index].loc,
                callee_name: partials[index].callee_name,
                receiver_path: partials[index].receiver_path,
                receiver_site: partials[index].receiver_site,
                receiver_taint: value,
                arguments: partials[index].arguments,
              })
              next_states.push(branch.state)
            }
            _ => escapes.push(branch)
          }
        }
      }
      partials = next_infos
      states = next_states
    }
    None => ()
  }
  let argument_items = match args_ast {
    { "children": Array(items), .. } => items
    _ => []
  }
  for arg_index in 0..<argument_items.length() {
    let next_infos : Array[CallInfo] = []
    let next_states : Array[TaintState] = []
    for info_index in 0..<partials.length() {
      match argument_items[arg_index] {
        {
          "kind": "Argument",
          "loc": arg_loc,
          "children": { "value": value_expr, "kind": arg_kind, .. },
          ..
        } => {
          let result = analyze_expr(value_expr, states[info_index], spec)
          for finding in result.findings {
            if !findings.contains(finding) {
              findings.push(finding)
            }
          }
          for branch in result.branches {
            match branch.exit {
              FlowExit::Normal(value) => {
                let arguments : Array[CallArgument] = []
                for existing in partials[info_index].arguments {
                  arguments.push(existing)
                }
                arguments.push({
                  index: partials[info_index].arguments.length(),
                  label: extract_argument_label(arg_kind),
                  expr: value_expr,
                  loc: arg_loc,
                  path: extract_storage_path(value_expr),
                  site: value_site_for_expr(value_expr),
                  taint: value,
                })
                next_infos.push({
                  kind: partials[info_index].kind,
                  ast: partials[info_index].ast,
                  loc: partials[info_index].loc,
                  callee_name: partials[info_index].callee_name,
                  receiver_path: partials[info_index].receiver_path,
                  receiver_site: partials[info_index].receiver_site,
                  receiver_taint: partials[info_index].receiver_taint,
                  arguments,
                })
                next_states.push(branch.state)
              }
              _ => escapes.push(branch)
            }
          }
        }
        _ => {
          next_infos.push(partials[info_index])
          next_states.push(states[info_index])
        }
      }
    }
    partials = next_infos
    states = next_states
  }
  let branches : Array[ExecBranch] = []
  for index in 0..<partials.length() {
    let transfer = apply_transfer(partials[index], states[index], spec)
    for finding in transfer.1 {
      if !findings.contains(finding) {
        findings.push(finding)
      }
    }
    branches.push({ state: transfer.0, exit: FlowExit::Normal(transfer.2) })
  }
  for escape in escapes {
    branches.push(escape)
  }
  { branches, findings }
}

///|
fn extract_argument_label(arg_kind : Json) -> String? {
  match arg_kind {
    {
      "kind": "ArgumentKind::Labelled",
      "children": {
        "value": {
          "kind": "Label",
          "children": { "name": String(name), .. },
          ..
        },
        ..
      },
      ..
    } => Some(name)
    _ => None
  }
}

///|
/// Apply custom or declarative call models, then mutate state according to
/// killed paths and emit the call's result taint.
fn apply_transfer(
  info : CallInfo,
  state : TaintState,
  spec : TaintSpec,
) -> (TaintState, Array[SinkFinding], TaintTree) {
  let transfer = match (spec.custom_transfer_call)(info) {
    Some(transfer) => transfer
    None =>
      match
        lower_declarative_call_transfer(
          info,
          spec.rule_id,
          spec.sources,
          spec.call_models,
        ) {
        Some(transfer) => transfer
        None => unknown_call_transfer(info, spec.unknown_call_policy)
      }
  }
  let return_taint = stamp_tree_rule_id(transfer.return_taint, spec.rule_id)
  let findings = stamp_findings_rule_id(transfer.findings, spec.rule_id)
  let mut next_state = state
  for path in transfer.killed_paths {
    next_state = state_kill_path(next_state, path)
  }
  (next_state, dedup_findings(findings), return_taint)
}

///|
/// Default behaviour for unmodeled calls.
///
/// `NoEffect` keeps calls transparent. `PropagateArgumentsToReturn` models a
/// generic passthrough helper where receiver and argument taint flow into the
/// return value.
fn unknown_call_transfer(
  info : CallInfo,
  policy : UnknownCallPolicy,
) -> CallTransfer {
  match policy {
    UnknownCallPolicy::NoEffect => empty_call_transfer()
    UnknownCallPolicy::PropagateArgumentsToReturn => {
      // Method-style calls should conservatively preserve receiver taint even
      // though the policy name only mentions arguments.
      let mut value = copy_tree(info.receiver_taint)
      for argument in info.arguments {
        value = tree_merge(value, argument.taint)
      }
      { return_taint: value, killed_paths: [], findings: [] }
    }
  }
}

///|
fn analyze_continue_expr(
  args_ast : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let items = match args_ast {
    { "children": Array(items), .. } => items
    _ => []
  }
  let mut partials : Array[(TaintState, Array[TaintTree])] = [(state, [])]
  let findings : Array[SinkFinding] = []
  let branches : Array[ExecBranch] = []
  for item in items {
    let next_partials : Array[(TaintState, Array[TaintTree])] = []
    for partial in partials {
      let result = analyze_expr(item, partial.0, spec)
      for finding in result.findings {
        if !findings.contains(finding) {
          findings.push(finding)
        }
      }
      for branch in result.branches {
        match branch.exit {
          FlowExit::Normal(value) => {
            let values : Array[TaintTree] = []
            for existing in partial.1 {
              values.push(copy_tree(existing))
            }
            values.push(copy_tree(value))
            next_partials.push((branch.state, values))
          }
          _ => branches.push(branch)
        }
      }
    }
    partials = next_partials
  }
  for partial in partials {
    branches.push({ state: partial.0, exit: FlowExit::Continue(partial.1) })
  }
  { branches, findings }
}

///|
/// Nested function-like bindings define fresh scopes that are not analyzed as
/// part of the current function body. Their binder names still shadow outer
/// roots, so the old roots must be killed while evaluating the remaining body.
fn analyze_boundary_binding_expr(
  binder : Json,
  body : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  match binder {
    { "kind": "Binder", "children": { "name": String(name), .. }, .. } =>
      analyze_expr(body, state_kill_roots(state, [name]), spec)
    _ => analyze_expr(body, state, spec)
  }
}

///|
/// Same as `analyze_boundary_binding_expr`, but for multi-binding forms.
fn analyze_boundary_bindings_expr(
  bindings : Json,
  body : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  analyze_expr(
    body,
    state_kill_roots(state, collect_binding_binder_names(bindings)),
    spec,
  )
}

///|
/// Conservative fallback for unhandled expression kinds.
///
/// The engine evaluates direct expression children in source order and merges
/// their resulting value taint. This keeps the analysis useful when v1 lacks a
/// dedicated transfer rule for a node kind.
fn analyze_unknown_expr(
  expr : Json,
  state : TaintState,
  spec : TaintSpec,
) -> ExecResult {
  let children = direct_expr_children(expr)
  if children.is_empty() {
    return normal_result(state)
  }
  let mut partials : Array[(TaintState, TaintTree)] = [(state, [])]
  let findings : Array[SinkFinding] = []
  let escapes : Array[ExecBranch] = []
  for child in children {
    let next_partials : Array[(TaintState, TaintTree)] = []
    for partial in partials {
      let result = analyze_expr(child, partial.0, spec)
      for finding in result.findings {
        if !findings.contains(finding) {
          findings.push(finding)
        }
      }
      for branch in result.branches {
        match branch.exit {
          FlowExit::Normal(value) =>
            next_partials.push((branch.state, tree_merge(partial.1, value)))
          _ => escapes.push(branch)
        }
      }
    }
    partials = next_partials
  }
  let branches : Array[ExecBranch] = []
  for partial in partials {
    branches.push({ state: partial.0, exit: FlowExit::Normal(partial.1) })
  }
  for escape in escapes {
    branches.push(escape)
  }
  { branches, findings }
}

///|
/// Collect immediate descendant expression nodes from an arbitrary AST node.
fn direct_expr_children(ast : Json) -> Array[Json] {
  let children : Array[Json] = []
  collect_direct_expr_children(json_children(ast), children)
  children
}

///|
fn collect_direct_expr_children(node : Json?, children : Array[Json]) -> Unit {
  match node {
    Some({ "kind": String(kind), .. } as child) =>
      if kind.has_prefix("Expr::") {
        children.push(child)
      } else {
        match json_children(child) {
          Some(Object(entries)) =>
            for _, value in entries.iter2() {
              collect_direct_expr_children(Some(value), children)
            }
          Some(Array(items)) =>
            for item in items {
              collect_direct_expr_children(Some(item), children)
            }
          _ => ()
        }
      }
    Some(Array(items)) =>
      for item in items {
        collect_direct_expr_children(Some(item), children)
      }
    Some(Object(entries)) =>
      for _, value in entries.iter2() {
        collect_direct_expr_children(Some(value), children)
      }
    _ => ()
  }
}

///|
fn copy_findings(findings : Array[SinkFinding]) -> Array[SinkFinding] {
  let copied : Array[SinkFinding] = []
  for finding in findings {
    copied.push(finding)
  }
  copied
}
