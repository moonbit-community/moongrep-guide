// White-box tests for internal domain operations.
//
// These tests bypass the public API and exercise state/path helpers directly so
// regressions in subtree kill/read semantics are caught without going through
// the full AST interpreter.

///|
/// Build a synthetic origin with a stable id for low-level domain assertions.
fn test_origin(path : StoragePath, id : String) -> TaintOrigin {
  { rule_id: "test", origin_id: id, site: ValueSite::Path(path), note: None }
}

///|
/// Construct absolute paths without relying on parser extraction.
fn test_path(root : String, segments : Array[PathSegment]) -> StoragePath {
  { root, segments }
}

///|
/// Collapse a taint tree into unique origins for easier assertions.
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
// Killing `x.a` must not delete taint stored under a sibling subtree `x.b`.
test "kill on child path does not affect sibling subtree" {
  let state = empty_state()
    |> state_write_path(test_path("x", [PathSegment::Field("a")]), [
      { path: [], origins: [test_origin(test_path("src", []), "a")] },
    ])
    |> state_write_path(test_path("x", [PathSegment::Field("b")]), [
      { path: [], origins: [test_origin(test_path("src", []), "b")] },
    ])
  let killed = state_kill_path(state, test_path("x", [PathSegment::Field("a")]))
  assert_eq(
    state_read_path(killed, test_path("x", [PathSegment::Field("a")])).length(),
    0,
  )
  let sibling = state_read_path(
    killed,
    test_path("x", [PathSegment::Field("b")]),
  )
  assert_eq(sibling.length(), 1)
  assert_eq(sibling[0].origins[0].origin_id, "b")
}

///|
// Dynamic reads should merge taint from both a specific index and the wildcard
// `AnyIndex` bucket.
test "dynamic read merges constant and any index taint" {
  let state = empty_state()
    |> state_write_path(test_path("arr", [PathSegment::ConstIndex("0")]), [
      { path: [], origins: [test_origin(test_path("src", []), "const")] },
    ])
    |> state_write_path(test_path("arr", [PathSegment::AnyIndex]), [
      { path: [], origins: [test_origin(test_path("src", []), "any")] },
    ])
  let dynamic = state_read_path(
    state,
    test_path("arr", [PathSegment::AnyIndex]),
  )
  let origins = tree_origins(dynamic)
  assert_eq(origins.length(), 2)
}
