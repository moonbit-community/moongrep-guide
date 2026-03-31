// Public provenance and sink-site types.
//
// Diagnostics no longer reuse storage paths for every situation. `ValueSite`
// describes where a value came from or where a sink consumed it, while
// `StoragePath` continues to model addressable state locations only.

///|
/// User-facing description of where a value originated or was consumed.
pub(all) enum ValueSite {
  Path(StoragePath)
  CallResult(String?, Json)
  Expr(Json, String?)
  Synthetic(String)
} derive(Eq, Show, ToJson)

///|
/// Provenance attached to taint.
///
/// A single flow can accumulate multiple origins when branches merge or when a
/// sink depends on more than one tainted input.
pub(all) struct TaintOrigin {
  rule_id : String
  origin_id : String
  site : ValueSite
  note : String?
} derive(Eq, Show, ToJson)

///|
/// A reported sink hit.
///
/// `sink_site` identifies the value consumed by the sink, while `origins`
/// explain where the taint came from.
pub(all) struct SinkFinding {
  rule_id : String
  sink_id : String
  sink_loc : Json
  sink_site : ValueSite
  origins : Array[TaintOrigin]
} derive(Eq, Show, ToJson)
