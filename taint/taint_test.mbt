// Black-box tests for the public taint API.
//
// These tests exercise the package the same way an external caller would:
// build a `TaintSpec`, analyze source text, and inspect only the exported
// result types. The transfer hook below models a tiny environment with sinks
// and a sanitizer so each test can focus on one propagation rule.

///|
/// Shared spec used by the black-box tests.
///
/// Every test chooses which entry paths start tainted and then reuses the same
/// custom call-model logic for sinks/sanitizers.
fn test_spec(
  seeds : Array[StoragePath],
  rule_id? : String = "test",
) -> TaintSpec {
  {
    rule_id,
    sources: seed_sources(seeds),
    call_models: [],
    unknown_call_policy: UnknownCallPolicy::NoEffect,
    max_fixpoint_iterations: 6,
    custom_transfer_call: test_transfer_call,
  }
}

///|
/// Convenience helper for whole-variable seeds.
fn root_path(root : String) -> StoragePath {
  { root, segments: [] }
}

///|
/// Convenience helper for path-sensitive seeds.
fn storage_path(root : String, segments : Array[PathSegment]) -> StoragePath {
  { root, segments }
}

///|
fn seed_sources(seeds : Array[StoragePath]) -> Array[SourceModel] {
  let sources : Array[SourceModel] = []
  for seed in seeds {
    sources.push(SourceModel::EntryPath(seed, "entry:\{seed.root}", None))
  }
  sources
}

///|
/// Collapse a relative taint tree into its unique origin set.
///
/// Black-box tests care about provenance identity, not the exact sparse-tree
/// layout, so this helper keeps assertions small.
fn tree_origins(tree : TaintTree) -> Array[TaintOrigin] {
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
/// Expect a site to be path-based and return the underlying storage path.
fn expect_path_site(site : ValueSite) -> StoragePath {
  match site {
    ValueSite::Path(path) => path
    _ => panic()
  }
}

///|
fn expect_path_site_root(site : ValueSite) -> String {
  expect_path_site(site).root
}

///|
fn assert_call_result_site(site : ValueSite, callee_name : String?) -> Unit {
  match site {
    ValueSite::CallResult(found_name, _) =>
      if found_name == callee_name {
        ()
      } else {
        panic()
      }
    _ => panic()
  }
}

///|
/// Create sink findings only when the selected argument is actually tainted.
fn sink_findings_for_argument(
  call : CallInfo,
  sink_id : String,
  arg_index : Int,
) -> Array[SinkFinding] {
  if call.arguments.length() <= arg_index {
    return []
  }
  let arg = call.arguments[arg_index]
  let origins = tree_origins(arg.taint)
  if origins.is_empty() {
    []
  } else {
    [
      {
        rule_id: "<transfer>",
        sink_id,
        sink_loc: call.loc,
        sink_site: arg.site,
        origins,
      },
    ]
  }
}

///|
/// Call-model used throughout the black-box suite.
///
/// - `sink` reads argument 0
/// - `sink2` reads argument 1 so pipe tests can verify argument ordering
/// - `sink_*` gives a family of sinks for control-flow tests
/// - `sanitize` kills the taint at its first argument path
fn test_transfer_call(call : CallInfo) -> CallTransfer? {
  match call.callee_name {
    Some(name) if name == "sink" =>
      Some({
        return_taint: [],
        killed_paths: [],
        findings: sink_findings_for_argument(call, name, 0),
      })
    Some(name) if name == "sink2" =>
      Some({
        return_taint: [],
        killed_paths: [],
        findings: sink_findings_for_argument(call, name, 1),
      })
    Some(name) if name.has_prefix("sink_") =>
      Some({
        return_taint: [],
        killed_paths: [],
        findings: sink_findings_for_argument(call, name, 0),
      })
    Some(name) if name == "sanitize" => {
      let killed_paths : Array[StoragePath] = []
      if !call.arguments.is_empty() {
        match call.arguments[0].path {
          Some(path) => killed_paths.push(path)
          None => ()
        }
      }
      Some({ return_taint: [], killed_paths, findings: [] })
    }
    _ => None
  }
}

///|
/// Parse and analyze exactly one function from source text.
fn first_result(
  source : String,
  seeds : Array[StoragePath],
) -> AnalysisResult raise {
  first_result_with_spec(source, test_spec(seeds))
}

///|
fn first_result_with_spec(
  source : String,
  spec : TaintSpec,
) -> AnalysisResult raise {
  let results = analyze_source_functions(name="test_source", source, spec)
  assert_eq(results.length(), 1)
  results[0]
}

///|
fn no_custom_transfer(_ : CallInfo) -> CallTransfer? {
  None
}

///|
fn declarative_spec(
  sources : Array[SourceModel],
  call_models : Array[CallModel],
  rule_id? : String = "test",
) -> TaintSpec {
  {
    rule_id,
    sources,
    call_models,
    unknown_call_policy: UnknownCallPolicy::NoEffect,
    max_fixpoint_iterations: 6,
    custom_transfer_call: no_custom_transfer,
  }
}

///|
/// Helper for tests that care about one sink appearing among several findings.
fn result_has_sink_id(result : AnalysisResult, sink_id : String) -> Bool {
  for finding in result.findings {
    if finding.sink_id == sink_id {
      return true
    }
  }
  false
}

///|
// Baseline propagation: taint on an entry parameter must survive a simple local
// alias before reaching a sink.
test "parameter taint propagates through local binding to sink" {
  let result = first_result(
    (
      #|pub fn foo(user : Int) -> Unit {
      #|  let alias = user
      #|  sink(alias)
      #|}
    ),
    [root_path("user")],
  )
  assert_eq(result.rule_id, "test")
  assert_eq(result.findings.length(), 1)
  let finding = result.findings[0]
  assert_eq(finding.rule_id, "test")
  assert_eq(finding.sink_id, "sink")
  assert_eq(expect_path_site_root(finding.sink_site), "alias")
  assert_eq(finding.origins.length(), 1)
  assert_eq(finding.origins[0].rule_id, "test")
  assert_eq(expect_path_site_root(finding.origins[0].site), "user")
}

///|
// Path sensitivity: taint on `input.a` should not be widened to the whole
// record when it flows through a local alias.
test "field-level taint propagates precisely" {
  let result = first_result(
    (
      #|pub fn foo(input : Pair) -> Unit {
      #|  let alias = input.a
      #|  sink(alias)
      #|}
    ),
    [storage_path("input", [PathSegment::Field("a")])],
  )
  assert_eq(result.findings.length(), 1)
  let finding = result.findings[0]
  assert_eq(expect_path_site_root(finding.sink_site), "alias")
  assert_eq(
    expect_path_site(finding.origins[0].site),
    storage_path("input", [PathSegment::Field("a")]),
  )
}

///|
// Read semantics for dynamic indices are intentionally conservative:
// reading `arr[i]` should observe taint stored at a precise constant index.
test "dynamic index read sees constant indexed taint" {
  let result = first_result(
    (
      #|pub fn foo(arr : Array[Int], i : Int) -> Unit {
      #|  sink(arr[i])
      #|}
    ),
    [storage_path("arr", [PathSegment::ConstIndex("0")])],
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(
    expect_path_site(result.findings[0].origins[0].site),
    storage_path("arr", [PathSegment::ConstIndex("0")]),
  )
}

///|
// Sanitizers clear the selected state path, so a later sink should no longer
// report the parameter origin.
test "sanitizer kill removes taint from later sink" {
  let result = first_result(
    (
      #|pub fn foo(user : Int) -> Unit {
      #|  sanitize(user)
      #|  sink(user)
      #|}
    ),
    [root_path("user")],
  )
  assert_eq(result.findings.length(), 0)
}

///|
// Branch joins are union-based: a sink after an `if` should report taint if any
// branch can assign a tainted value to the joined variable.
test "if branches merge conservatively" {
  let result = first_result(
    (
      #|pub fn foo(user : Int, flag : Bool) -> Unit {
      #|  let mut current = 0
      #|  if flag {
      #|    current = user
      #|  } else {
      #|    current = 0
      #|  }
      #|  sink(current)
      #|}
    ),
    [root_path("user")],
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(expect_path_site_root(result.findings[0].sink_site), "current")
}

///|
// `is`-patterns in `if` conditions should bind names only on the true branch,
// making the bound value available inside the then block.
test "if is-condition binds pattern for then branch" {
  let result = first_result(
    (
      #|pub fn foo(x : Int?) -> Unit {
      #|  if x is Some(y) {
      #|    sink(y)
      #|  } else {
      #|    ()
      #|  }
      #|}
    ),
    [root_path("x")],
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(expect_path_site_root(result.findings[0].sink_site), "y")
  assert_eq(expect_path_site_root(result.findings[0].origins[0].site), "x")
}

///|
// `Some((_, right))` should refine into the payload tuple rather than copying
// the whole option taint to every binder.
test "if is-condition refines Some tuple payload" {
  let result = first_result(
    (
      #|pub fn foo(x : (Int, Int)?) -> Unit {
      #|  if x is Some((_, right)) {
      #|    sink(right)
      #|  } else {
      #|    ()
      #|  }
      #|}
    ),
    [storage_path("x", [PathSegment::TupleIndex(0)])],
  )
  assert_eq(result.findings.length(), 0)
}

///|
// Guard conditions expose `is`-bound names to the guard body.
test "guard is-condition binds pattern for body" {
  let result = first_result(
    (
      #|pub fn foo(x : Int?) -> Unit {
      #|  guard x is Some(y) else { () };
      #|  sink(y)
      #|}
    ),
    [root_path("x")],
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(expect_path_site_root(result.findings[0].sink_site), "y")
  assert_eq(expect_path_site_root(result.findings[0].origins[0].site), "x")
}

///|
// `while` loop conditions should also bind `is`-pattern names for the loop body.
test "while is-condition binds pattern for loop body" {
  let result = first_result(
    (
      #|pub fn foo(x : Int?) -> Unit {
      #|  while x is Some(y) {
      #|    sink(y)
      #|  }
      #|}
    ),
    [root_path("x")],
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(expect_path_site_root(result.findings[0].sink_site), "y")
  assert_eq(expect_path_site_root(result.findings[0].origins[0].site), "x")
}

///|
// Case guards can introduce extra `is`-pattern binders beyond the arm pattern.
test "match guard is-condition binds pattern for arm body" {
  let result = first_result(
    (
      #|pub fn foo(x : Int??) -> Unit {
      #|  match x {
      #|    Some(v) if v is Some(inner) => sink(inner)
      #|    _ => ()
      #|  }
      #|}
    ),
    [root_path("x")],
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(expect_path_site_root(result.findings[0].sink_site), "inner")
  assert_eq(expect_path_site_root(result.findings[0].origins[0].site), "x")
}

///|
// Catch guards use the same condition-binding rules as match guards.
test "catch guard is-condition binds pattern for arm body" {
  let result = first_result(
    (
      #|pub fn foo(x : Int??) -> Unit {
      #|  try {
      #|    raise(x)
      #|  } catch {
      #|    err if err is Some(inner) => sink(inner)
      #|  }
      #|}
    ),
    [root_path("x")],
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(expect_path_site_root(result.findings[0].sink_site), "inner")
  assert_eq(expect_path_site_root(result.findings[0].origins[0].site), "x")
}

///|
// The temporary binder created by an `if` condition must not overwrite the
// outer variable with the same name after the `if` expression completes.
test "if is-condition binder shadow does not leak to outer variable" {
  let result = first_result(
    (
      #|pub fn foo(x : Int?, y : Int) -> Unit {
      #|  if x is Some(y) {
      #|    ()
      #|  } else {
      #|    ()
      #|  }
      #|  sink(y)
      #|}
    ),
    [root_path("y")],
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(result.findings[0].origins.length(), 1)
  assert_eq(expect_path_site_root(result.findings[0].origins[0].site), "y")
}

///|
// Loop-condition binders are scoped to the loop body and must not leak to the
// state observed after the loop exits.
test "while is-condition binder shadow does not leak after loop" {
  let result = first_result(
    (
      #|pub fn foo(x : Int?, y : Int) -> Unit {
      #|  while x is Some(y) {
      #|    ()
      #|  }
      #|  sink(y)
      #|}
    ),
    [root_path("y")],
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(result.findings[0].origins.length(), 1)
  assert_eq(expect_path_site_root(result.findings[0].origins[0].site), "y")
}

///|
// `foreach` reads an abstract element view from the collection and binds it to
// the loop variable.
test "foreach loop propagates element taint to binder" {
  let result = first_result(
    (
      #|pub fn foo(arr : Array[Int]) -> Unit {
      #|  for item in arr {
      #|    sink(item)
      #|  }
      #|}
    ),
    [storage_path("arr", [PathSegment::ConstIndex("0")])],
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(expect_path_site_root(result.findings[0].sink_site), "item")
}

///|
// Pipe syntax prepends the lhs as synthetic argument 0, so the explicit rhs
// argument must still remain at index 1.
test "pipe evaluates explicit rhs argument taint" {
  let result = first_result(
    (
      #|pub fn foo(x : Int, user : Int) -> Unit {
      #|  x |> sink2(user)
      #|}
    ),
    [root_path("user")],
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(result.findings[0].sink_id, "sink2")
  assert_eq(expect_path_site_root(result.findings[0].sink_site), "user")
}

///|
// Side effects inside explicit rhs arguments must run before the call summary
// is applied to the overall pipe expression.
test "pipe evaluates explicit rhs argument side effects" {
  let result = first_result(
    (
      #|pub fn foo(x : Int, user : Int) -> Unit {
      #|  x |> passthrough(sanitize(user))
      #|  sink(user)
      #|}
    ),
    [root_path("user")],
  )
  assert_eq(result.findings.length(), 0)
}

///|
// The callee expression itself can have side effects; they must happen before
// the enclosing apply is summarized.
test "callee expression side effects run before apply transfer" {
  let result = first_result(
    (
      #|pub fn foo(user : Int) -> Unit {
      #|  (sanitize(user))(0)
      #|  sink(user)
      #|}
    ),
    [root_path("user")],
  )
  assert_eq(result.findings.length(), 0)
}

///|
// Pattern binders shadow outer variables only inside the matched arm. The outer
// `i` must be restored after the match finishes.
test "match binder shadow does not leak to outer variable" {
  let result = first_result(
    (
      #|pub fn foo(v : Int?, i : Int) -> Unit {
      #|  match v {
      #|    Some(i) => sink(i)
      #|    None => ()
      #|  }
      #|  sink(i)
      #|}
    ),
    [root_path("v")],
  )
  assert_eq(result.findings.length(), 1)
}

///|
// Ordinary `match` should apply the same `Some` payload refinement as `is`.
test "match refines Some tuple payload" {
  let result = first_result(
    (
      #|pub fn foo(x : (Int, Int)?) -> Unit {
      #|  match x {
      #|    Some((_, right)) => sink(right)
      #|    None => ()
      #|  }
      #|}
    ),
    [storage_path("x", [PathSegment::TupleIndex(0)])],
  )
  assert_eq(result.findings.length(), 0)
}

///|
// Catch binders also create a scoped shadow that must not overwrite the outer
// variable once the catch arm completes.
test "catch binder shadow does not leak to outer variable" {
  let result = first_result(
    (
      #|pub fn foo(user : Int, err : Int) -> Unit {
      #|  try {
      #|    raise(user)
      #|  } catch {
      #|    err => sink(err)
      #|  }
      #|  sink(err)
      #|}
    ),
    [root_path("user")],
  )
  assert_eq(result.findings.length(), 1)
}

///|
// If an inner catch guard fails, the raised value must continue outward so an
// outer catch can still observe the original taint.
test "inner catch preserves raise to outer catch" {
  let result = first_result(
    (
      #|pub fn foo(user : Int) -> Unit {
      #|  try {
      #|    try {
      #|      raise(user)
      #|    } catch {
      #|      err if false => sink_inner(err)
      #|    }
      #|  } catch {
      #|    outer => sink_outer(outer)
      #|  }
      #|}
    ),
    [root_path("user")],
  )
  assert_eq(result_has_sink_id(result, "sink_outer"), true)
}

///|
// Nested function bodies are analysis boundaries in v1, so sink activity inside
// a lambda must not be merged into the enclosing function's findings.
test "nested lambda body is not merged into outer analysis" {
  let result = first_result(
    (
      #|pub fn foo(user : Int) -> Int {
      #|  let f = fn(x : Int) -> Int { sink(user); x }
      #|  f(user)
      #|}
    ),
    [root_path("user")],
  )
  assert_eq(result.findings.length(), 0)
}

///|
fn find_result_for_rule(
  results : Array[AnalysisResult],
  rule_id : String,
) -> AnalysisResult? {
  for result in results {
    if result.rule_id == rule_id {
      return Some(result)
    }
  }
  None
}

///|
// Multi-rule execution should keep taint states isolated so each rule only sees
// its own seeded source.
test "multi-rule analysis isolates rule state per execution" {
  let results = analyze_source_functions_multi(
    name="test_source",
    (
      #|pub fn foo(user : Int, admin : Int) -> Unit {
      #|  sink(user)
      #|  sink(admin)
      #|}
    ),
    [
      test_spec([root_path("user")], rule_id="rule.user"),
      test_spec([root_path("admin")], rule_id="rule.admin"),
    ],
  )
  assert_eq(results.length(), 2)
  guard find_result_for_rule(results, "rule.user") is Some(user_result) else {
    fail("missing result for rule.user")
  }
  guard find_result_for_rule(results, "rule.admin") is Some(admin_result) else {
    fail("missing result for rule.admin")
  }
  assert_eq(user_result.findings.length(), 1)
  assert_eq(user_result.findings[0].rule_id, "rule.user")
  assert_eq(expect_path_site_root(user_result.findings[0].sink_site), "user")
  assert_eq(user_result.findings[0].origins[0].rule_id, "rule.user")
  assert_eq(admin_result.findings.length(), 1)
  assert_eq(admin_result.findings[0].rule_id, "rule.admin")
  assert_eq(expect_path_site_root(admin_result.findings[0].sink_site), "admin")
  assert_eq(admin_result.findings[0].origins[0].rule_id, "rule.admin")
}

///|
// Declarative call-return sources should report provenance at the call result
// instead of forcing a synthetic storage path.
test "declarative call-return source keeps call-result provenance" {
  let spec = declarative_spec(
    [
      SourceModel::CallReturn(
        CallMatcher::CalleeName("input"),
        "input",
        Some("input()"),
        [],
      ),
    ],
    [
      {
        matcher: CallMatcher::CalleeName("sink"),
        effects: [CallEffect::ReportSinkArg("sink", 0)],
      },
    ],
  )
  let result = first_result_with_spec(
    (
      #|pub fn foo() -> Unit {
      #|  let x = input()
      #|  sink(x)
      #|}
    ),
    spec,
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(expect_path_site_root(result.findings[0].sink_site), "x")
  assert_call_result_site(result.findings[0].origins[0].site, Some("input"))
}

///|
// `sink(input())` should report the consumed value as a call result site rather
// than fabricating a placeholder path.
test "declarative sink on call expression uses call-result site" {
  let spec = declarative_spec(
    [
      SourceModel::CallReturn(
        CallMatcher::CalleeName("input"),
        "input",
        Some("input()"),
        [],
      ),
    ],
    [
      {
        matcher: CallMatcher::CalleeName("sink"),
        effects: [CallEffect::ReportSinkArg("sink", 0)],
      },
    ],
  )
  let result = first_result_with_spec(
    (
      #|pub fn foo() -> Unit {
      #|  sink(input())
      #|}
    ),
    spec,
  )
  assert_eq(result.findings.length(), 1)
  assert_call_result_site(result.findings[0].sink_site, Some("input"))
  assert_call_result_site(result.findings[0].origins[0].site, Some("input"))
}

///|
// Declarative propagation from argument to return must preserve provenance from
// the original call-return source.
test "declarative arg-to-return propagation preserves provenance" {
  let spec = declarative_spec(
    [
      SourceModel::CallReturn(
        CallMatcher::CalleeName("input"),
        "input",
        Some("input()"),
        [],
      ),
    ],
    [
      {
        matcher: CallMatcher::CalleeName("id"),
        effects: [CallEffect::PropagateArgToReturn(0)],
      },
      {
        matcher: CallMatcher::CalleeName("sink"),
        effects: [CallEffect::ReportSinkArg("sink", 0)],
      },
    ],
  )
  let result = first_result_with_spec(
    (
      #|pub fn foo() -> Unit {
      #|  let x = id(input())
      #|  sink(x)
      #|}
    ),
    spec,
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(expect_path_site_root(result.findings[0].sink_site), "x")
  assert_call_result_site(result.findings[0].origins[0].site, Some("input"))
}

///|
// Declarative sanitizers should be able to kill a storage path without a
// custom transfer hook.
test "declarative sanitizer kill removes taint from later sink" {
  let spec = declarative_spec(
    [SourceModel::EntryPath(root_path("user"), "user", None)],
    [
      {
        matcher: CallMatcher::CalleeName("sanitize"),
        effects: [CallEffect::KillArg(0)],
      },
      {
        matcher: CallMatcher::CalleeName("sink"),
        effects: [CallEffect::ReportSinkArg("sink", 0)],
      },
    ],
  )
  let result = first_result_with_spec(
    (
      #|pub fn foo(user : Int) -> Unit {
      #|  sanitize(user)
      #|  sink(user)
      #|}
    ),
    spec,
  )
  assert_eq(result.findings.length(), 0)
}

///|
// Receiver-style sources should also be first-class in the declarative model.
test "declarative receiver method source works" {
  let spec = declarative_spec(
    [
      SourceModel::CallReturn(
        CallMatcher::MethodName("source_method"),
        "source_method",
        Some("source_method()"),
        [],
      ),
    ],
    [
      {
        matcher: CallMatcher::CalleeName("sink"),
        effects: [CallEffect::ReportSinkArg("sink", 0)],
      },
    ],
  )
  let result = first_result_with_spec(
    (
      #|pub fn foo(obj : Obj) -> Unit {
      #|  let x = obj.source_method()
      #|  sink(x)
      #|}
    ),
    spec,
  )
  assert_eq(result.findings.length(), 1)
  assert_eq(expect_path_site_root(result.findings[0].sink_site), "x")
  assert_call_result_site(
    result.findings[0].origins[0].site,
    Some("source_method"),
  )
}
