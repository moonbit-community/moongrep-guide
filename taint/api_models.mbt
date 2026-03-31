// Public taint-value, call-model, and rule-spec types.

///|
/// A tainted subtree relative to the value currently being described.
///
/// An empty `path` means "the value itself is tainted". Non-empty paths mean a
/// descendant of the current value carries taint.
pub(all) struct RelativeTaint {
  path : Array[PathSegment]
  origins : Array[TaintOrigin]
} derive(Eq, Show, ToJson)

///|
/// Sparse representation of a tainted value.
///
/// The engine stores only the tainted leaves/subtrees it knows about and merges
/// entries with the same relative path.
pub type TaintTree = Array[RelativeTaint]

///|
/// A reported result for one top-level function-like node.
///
/// The engine currently reports sink findings only; return-value taint is
/// tracked internally to evaluate control-flow and call summaries. Impl methods
/// are reported as `Owner::method`.
pub struct AnalysisResult {
  rule_id : String
  function_name : String
  function_loc : Json
  findings : Array[SinkFinding]
} derive(Eq, Show, ToJson)

///|
/// Call syntax shape as observed by the engine.
///
/// The distinction matters because pipe and dot-apply expose arguments and
/// receiver values differently when building a `CallInfo`. In particular, pipe
/// syntax turns the left-hand side into synthetic argument 0.
pub enum CallKind {
  Apply
  DotApply
  Pipe
} derive(Eq, Show, ToJson)

///|
/// One argument as seen by the call-model layer.
///
/// `path` is only present when the argument expression can be reduced to a
/// concrete storage path such as `x`, `x.a`, or `arr[i]`.
pub struct CallArgument {
  index : Int
  label : String?
  expr : Json
  loc : Json
  path : StoragePath?
  site : ValueSite
  taint : TaintTree
} derive(Eq, Show, ToJson)

///|
/// Snapshot of a call site delivered to declarative models and the optional
/// custom transfer hook.
///
/// The engine evaluates callee/receiver/arguments in source order first, then
/// applies `custom_transfer_call`, `call_models`, or `unknown_call_policy`.
/// `receiver_*` is populated for method-call shapes, while pipe syntax passes
/// its left-hand side as synthetic argument 0.
pub struct CallInfo {
  kind : CallKind
  ast : Json
  loc : Json
  callee_name : String?
  receiver_path : StoragePath?
  receiver_site : ValueSite?
  receiver_taint : TaintTree
  arguments : Array[CallArgument]
} derive(Eq, Show, ToJson)

///|
/// Low-level transfer summary produced by declarative lowering or a custom hook.
///
/// `return_taint` becomes the value of the call expression.
/// `killed_paths` removes taint from state after the call (sanitizers).
/// `findings` emits sink reports associated with the call.
pub(all) struct CallTransfer {
  return_taint : TaintTree
  killed_paths : Array[StoragePath]
  findings : Array[SinkFinding]
} derive(Eq, Show, ToJson)

///|
/// Fallback behaviour when no declarative or custom model recognizes a call.
///
/// `PropagateArgumentsToReturn` keeps the name for brevity, but the fallback
/// also merges receiver taint into the return value for method-style calls.
pub(all) enum UnknownCallPolicy {
  NoEffect
  PropagateArgumentsToReturn
} derive(Eq, Show, ToJson)

///|
/// Minimal matcher used by declarative source and call models.
pub(all) enum CallMatcher {
  CalleeName(String)
  MethodName(String)
  AnyCall
} derive(Eq, Show, ToJson)

///|
/// Declarative source model.
///
/// `EntryPath` replaces entry seeding. `CallReturn` promotes "this call returns
/// a tainted value" to a first-class concept.
pub(all) enum SourceModel {
  EntryPath(StoragePath, String, String?)
  CallReturn(CallMatcher, String, String?, Array[PathSegment])
} derive(Eq, Show, ToJson)

///|
/// Declarative call model applied after source matching.
pub(all) struct CallModel {
  matcher : CallMatcher
  effects : Array[CallEffect]
} derive(Eq, Show, ToJson)

///|
/// Common call effects lowered to `CallTransfer`.
pub(all) enum CallEffect {
  ReturnFreshSource(String, String?, Array[PathSegment])
  PropagateArgToReturn(Int)
  PropagateReceiverToReturn
  PropagateArgSubpathToReturn(Int, Array[PathSegment])
  KillArg(Int)
  KillReceiver
  ReportSinkArg(String, Int)
  ReportSinkReceiver(String)
} derive(Eq, Show, ToJson)

///|
/// User-supplied analysis configuration.
///
/// `sources` models both entry sources and call-return sources.
/// `call_models` covers common propagation, sink, and sanitizer behaviour.
/// `custom_transfer_call` is the low-level escape hatch for complex rules.
/// `unknown_call_policy` controls the default for unmodeled calls, including
/// whether receiver/argument taint is forwarded to the return value.
/// `max_fixpoint_iterations` bounds loop convergence work.
pub(all) struct TaintSpec {
  rule_id : String
  sources : Array[SourceModel]
  call_models : Array[CallModel]
  unknown_call_policy : UnknownCallPolicy
  max_fixpoint_iterations : Int
  custom_transfer_call : (CallInfo) -> CallTransfer?
}

///|
/// Internal helper for the "unknown call has no effect" policy.
fn empty_call_transfer() -> CallTransfer {
  { return_taint: [], killed_paths: [], findings: [] }
}
