// Declarative model lowering for taint call semantics.
//
// This file turns high-level `SourceModel` / `CallModel` descriptions into the
// low-level `CallTransfer` that the existing engine already understands.

///|
fn lower_declarative_call_transfer(
  info : CallInfo,
  rule_id : String,
  sources : Array[SourceModel],
  call_models : Array[CallModel],
) -> CallTransfer? {
  let mut matched = false
  let mut return_taint : TaintTree = []
  let killed_paths : Array[StoragePath] = []
  let findings : Array[SinkFinding] = []
  for source in sources {
    match source {
      SourceModel::EntryPath(_, _, _) => ()
      SourceModel::CallReturn(matcher, source_id, note, subpath) =>
        if call_matcher_matches(matcher, info) {
          matched = true
          return_taint = tree_merge(
            return_taint,
            fresh_call_return_taint(info, rule_id, source_id, note, subpath),
          )
        }
    }
  }
  for model in call_models {
    if !call_matcher_matches(model.matcher, info) {
      continue
    }
    matched = true
    for effect in model.effects {
      match effect {
        CallEffect::ReturnFreshSource(source_id, note, subpath) =>
          return_taint = tree_merge(
            return_taint,
            fresh_call_return_taint(info, rule_id, source_id, note, subpath),
          )
        CallEffect::PropagateArgToReturn(arg_index) =>
          match info.arguments.get(arg_index) {
            Some(argument) =>
              return_taint = tree_merge(return_taint, argument.taint)
            None => ()
          }
        CallEffect::PropagateReceiverToReturn =>
          return_taint = tree_merge(return_taint, info.receiver_taint)
        CallEffect::PropagateArgSubpathToReturn(arg_index, subpath) =>
          match info.arguments.get(arg_index) {
            Some(argument) =>
              return_taint = tree_merge(
                return_taint,
                tree_project(argument.taint, subpath),
              )
            None => ()
          }
        CallEffect::KillArg(arg_index) =>
          match info.arguments.get(arg_index) {
            Some(argument) =>
              match argument.path {
                Some(path) => add_storage_path_unique(killed_paths, path)
                None => ()
              }
            None => ()
          }
        CallEffect::KillReceiver =>
          match info.receiver_path {
            Some(path) => add_storage_path_unique(killed_paths, path)
            None => ()
          }
        CallEffect::ReportSinkArg(sink_id, arg_index) =>
          match info.arguments.get(arg_index) {
            Some(argument) =>
              add_sink_finding_if_tainted(
                findings,
                rule_id,
                sink_id,
                info.loc,
                argument.site,
                argument.taint,
              )
            None => ()
          }
        CallEffect::ReportSinkReceiver(sink_id) =>
          match info.receiver_site {
            Some(site) =>
              add_sink_finding_if_tainted(
                findings,
                rule_id,
                sink_id,
                info.loc,
                site,
                info.receiver_taint,
              )
            None => ()
          }
      }
    }
  }
  if matched {
    Some({ return_taint, killed_paths, findings: dedup_findings(findings) })
  } else {
    None
  }
}

///|
fn call_matcher_matches(matcher : CallMatcher, info : CallInfo) -> Bool {
  match matcher {
    CallMatcher::AnyCall => true
    CallMatcher::CalleeName(name) =>
      match info.callee_name {
        Some(callee_name) => callee_name == name
        None => false
      }
    CallMatcher::MethodName(name) =>
      match (info.receiver_site, info.callee_name) {
        (Some(_), Some(callee_name)) => callee_name == name
        _ => false
      }
  }
}

///|
fn fresh_call_return_taint(
  info : CallInfo,
  rule_id : String,
  source_id : String,
  note : String?,
  subpath : Array[PathSegment],
) -> TaintTree {
  [
    {
      path: copy_segments(subpath),
      origins: [
        {
          rule_id,
          origin_id: source_id,
          site: ValueSite::CallResult(info.callee_name, info.loc),
          note,
        },
      ],
    },
  ]
}

///|
fn add_storage_path_unique(
  paths : Array[StoragePath],
  path : StoragePath,
) -> Unit {
  if !paths.contains(path) {
    paths.push(path)
  }
}

///|
fn add_sink_finding_if_tainted(
  findings : Array[SinkFinding],
  rule_id : String,
  sink_id : String,
  sink_loc : Json,
  sink_site : ValueSite,
  taint : TaintTree,
) -> Unit {
  let origins = taint_tree_origins(taint)
  if origins.is_empty() {
    return
  }
  let finding = { rule_id, sink_id, sink_loc, sink_site, origins }
  if !findings.contains(finding) {
    findings.push(finding)
  }
}

///|
fn taint_tree_origins(tree : TaintTree) -> Array[TaintOrigin] {
  let origins : Array[TaintOrigin] = []
  for entry in tree {
    for origin in entry.origins {
      if !origins.contains(origin) {
        origins.push(origin)
      }
    }
  }
  origins
}

///|
fn value_site_for_expr(expr : Json) -> ValueSite {
  match extract_storage_path(expr) {
    Some(path) => ValueSite::Path(path)
    None =>
      match call_result_site_for_expr(expr) {
        Some(site) => site
        None => ValueSite::Expr(json_loc(expr), expr_site_summary(expr))
      }
  }
}

///|
fn call_result_site_for_expr(expr : Json) -> ValueSite? {
  match expr {
    { "kind": "Expr::Apply", "children": { "func": func, .. }, .. } =>
      Some(
        ValueSite::CallResult(extract_call_target_name(func), json_loc(expr)),
      )
    {
      "kind": "Expr::DotApply",
      "children": { "method_name": method_name, .. },
      ..
    } =>
      Some(
        ValueSite::CallResult(extract_label_name(method_name), json_loc(expr)),
      )
    { "kind": "Expr::Pipe", "children": { "rhs": rhs, .. }, .. } =>
      Some(ValueSite::CallResult(pipe_callee_name(rhs), json_loc(expr)))
    _ => None
  }
}

///|
fn pipe_callee_name(rhs : Json) -> String? {
  match rhs {
    { "kind": "Expr::Apply", "children": { "func": func, .. }, .. } =>
      extract_call_target_name(func)
    {
      "kind": "Expr::DotApply",
      "children": { "method_name": method_name, .. },
      ..
    } => extract_label_name(method_name)
    _ => extract_call_target_name(rhs)
  }
}

///|
fn expr_site_summary(expr : Json) -> String? {
  match expr {
    { "kind": String(kind), .. } => Some(kind)
    _ => None
  }
}
