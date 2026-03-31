// Public path types for taint state.
//
// `StoragePath` is the precise, state-level notion of "where taint lives inside
// the current function".

///|
/// A single step in a precise storage path.
///
/// Paths are always rooted at a local variable or parameter. Segments refine
/// the location to a field, tuple slot, constant index, or "some index".
pub(all) enum PathSegment {
  Field(String)
  TupleIndex(Int)
  ConstIndex(String)
  AnyIndex
} derive(Eq, Show, ToJson)

///|
/// An absolute program location inside the current function.
///
/// `root` is the local variable / parameter name. `segments` walk from that
/// root to a more precise sub-location.
pub(all) struct StoragePath {
  root : String
  segments : Array[PathSegment]
} derive(Eq, Show, ToJson)
