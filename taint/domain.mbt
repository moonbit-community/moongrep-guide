// Core taint domain and state operations.
//
// The engine stores taint as a sparse map:
//   absolute access path -> set of origins
//
// Reads project absolute state into a relative `TaintTree`, while writes kill a
// subtree and then re-attach the incoming relative tree under the written path.
// This file also implements pattern binding, branch merge, and loop-equivalence
// checks used by the control-flow engine.

///|
/// One absolute taint fact inside the current state.
priv struct StateEntry {
  path : StoragePath
  origins : Array[TaintOrigin]
}

///|
/// Sparse state keyed by absolute access path.
priv struct TaintState {
  entries : Array[StateEntry]
}

///|
/// Result of binding one variable name during pattern destructuring.
priv struct PatternBinding {
  name : String
  value : TaintTree
}

///|
fn empty_state() -> TaintState {
  { entries: [] }
}

///|
fn copy_segments(segments : Array[PathSegment]) -> Array[PathSegment] {
  let copied : Array[PathSegment] = []
  for segment in segments {
    copied.push(segment)
  }
  copied
}

///|
fn copy_tree(tree : TaintTree) -> TaintTree {
  let copied : TaintTree = []
  for entry in tree {
    copied.push({
      path: copy_segments(entry.path),
      origins: copy_origins(entry.origins),
    })
  }
  copied
}

///|
fn copy_origins(origins : Array[TaintOrigin]) -> Array[TaintOrigin] {
  let copied : Array[TaintOrigin] = []
  for origin in origins {
    copied.push(origin)
  }
  copied
}

///|
fn storage_path(root : String) -> StoragePath {
  { root, segments: [] }
}

///|
/// Render a stable key for deduplicating absolute paths.
fn storage_path_key(path : StoragePath) -> String {
  "\{path.root}\{segments_key(path.segments)}"
}

///|
fn segments_key(segments : Array[PathSegment]) -> String {
  let rendered : Array[String] = []
  for segment in segments {
    rendered.push(segment_key(segment))
  }
  rendered.join("/")
}

///|
fn segment_key(segment : PathSegment) -> String {
  match segment {
    PathSegment::Field(name) => "f:\{name}"
    PathSegment::TupleIndex(index) => "t:\{index}"
    PathSegment::ConstIndex(index) => "i:\{index}"
    PathSegment::AnyIndex => "i:*"
  }
}

///|
/// Read matching is intentionally more permissive than write matching.
///
/// A dynamic read `arr[i]` must see both `arr[*]` and precise constant entries
/// such as `arr[0]`, so `AnyIndex` and `ConstIndex` can match each other on
/// reads. Writes stay exact to avoid deleting unrelated siblings.
fn path_prefix_match_for_read(
  path_segments : Array[PathSegment],
  prefix_segments : Array[PathSegment],
) -> Bool {
  if prefix_segments.length() > path_segments.length() {
    return false
  }
  for index in 0..<prefix_segments.length() {
    if !segment_matches_for_read(prefix_segments[index], path_segments[index]) {
      return false
    }
  }
  true
}

///|
/// Exact prefix match used by writes and kills.
fn path_prefix_match_for_write(
  path_segments : Array[PathSegment],
  prefix_segments : Array[PathSegment],
) -> Bool {
  if prefix_segments.length() > path_segments.length() {
    return false
  }
  for index in 0..<prefix_segments.length() {
    if path_segments[index] != prefix_segments[index] {
      return false
    }
  }
  true
}

///|
/// Compare path segments under the read semantics described above.
fn segment_matches_for_read(query : PathSegment, actual : PathSegment) -> Bool {
  match query {
    PathSegment::AnyIndex =>
      match actual {
        PathSegment::AnyIndex | PathSegment::ConstIndex(_) => true
        _ => false
      }
    PathSegment::ConstIndex(index) =>
      match actual {
        PathSegment::ConstIndex(found) => found == index
        PathSegment::AnyIndex => true
        _ => false
      }
    _ => query == actual
  }
}

///|
fn strip_segments_prefix(
  segments : Array[PathSegment],
  prefix : Array[PathSegment],
) -> Array[PathSegment] {
  let stripped : Array[PathSegment] = []
  for index in prefix.length()..<segments.length() {
    stripped.push(segments[index])
  }
  stripped
}

///|
fn append_segments(
  left : Array[PathSegment],
  right : Array[PathSegment],
) -> Array[PathSegment] {
  let result : Array[PathSegment] = []
  for segment in left {
    result.push(segment)
  }
  for segment in right {
    result.push(segment)
  }
  result
}

///|
fn add_origin_unique(
  origins : Array[TaintOrigin],
  origin : TaintOrigin,
) -> Unit {
  if !origins.contains(origin) {
    origins.push(origin)
  }
}

///|
fn merge_origin_lists(
  left : Array[TaintOrigin],
  right : Array[TaintOrigin],
) -> Array[TaintOrigin] {
  let merged = copy_origins(left)
  for origin in right {
    add_origin_unique(merged, origin)
  }
  merged
}

///|
/// Merge a relative taint entry by path, unioning origin sets on collision.
fn merge_relative_entry(
  tree : TaintTree,
  path : Array[PathSegment],
  origins : Array[TaintOrigin],
) -> Unit {
  let key = segments_key(path)
  for index in 0..<tree.length() {
    if segments_key(tree[index].path) == key {
      tree[index] = {
        path: copy_segments(tree[index].path),
        origins: merge_origin_lists(tree[index].origins, origins),
      }
      return
    }
  }
  tree.push({ path: copy_segments(path), origins: copy_origins(origins) })
}

///|
/// Merge one absolute state entry by path, unioning origin sets on collision.
fn merge_state_entry(
  entries : Array[StateEntry],
  path : StoragePath,
  origins : Array[TaintOrigin],
) -> Unit {
  let key = storage_path_key(path)
  for index in 0..<entries.length() {
    if storage_path_key(entries[index].path) == key {
      entries[index] = {
        path,
        origins: merge_origin_lists(entries[index].origins, origins),
      }
      return
    }
  }
  entries.push({ path, origins: copy_origins(origins) })
}

///|
fn tree_merge(left : TaintTree, right : TaintTree) -> TaintTree {
  let merged = copy_tree(left)
  for entry in right {
    merge_relative_entry(merged, entry.path, entry.origins)
  }
  merged
}

///|
/// Project an absolute path from state into a value-relative taint tree.
///
/// For example, if state contains `x.a.b`, reading `x.a` returns a tree with
/// one relative entry `b`.
fn state_read_path(state : TaintState, path : StoragePath) -> TaintTree {
  let projected : TaintTree = []
  for entry in state.entries {
    if entry.path.root != path.root {
      continue
    }
    if path_prefix_match_for_read(entry.path.segments, path.segments) {
      merge_relative_entry(
        projected,
        strip_segments_prefix(entry.path.segments, path.segments),
        entry.origins,
      )
    }
  }
  projected
}

///|
/// Project a subtree from a relative taint tree.
fn tree_project(tree : TaintTree, prefix : Array[PathSegment]) -> TaintTree {
  let projected : TaintTree = []
  for entry in tree {
    if path_prefix_match_for_read(entry.path, prefix) {
      merge_relative_entry(
        projected,
        strip_segments_prefix(entry.path, prefix),
        entry.origins,
      )
    }
  }
  projected
}

///|
/// Re-root a relative taint tree under an additional prefix.
fn tree_prefix(tree : TaintTree, prefix : Array[PathSegment]) -> TaintTree {
  let prefixed : TaintTree = []
  for entry in tree {
    merge_relative_entry(
      prefixed,
      append_segments(prefix, entry.path),
      entry.origins,
    )
  }
  prefixed
}

///|
/// Remove a written subtree from state before applying the new value.
fn state_kill_path(state : TaintState, path : StoragePath) -> TaintState {
  let kept : Array[StateEntry] = []
  for entry in state.entries {
    let should_drop = entry.path.root == path.root &&
      path_prefix_match_for_write(entry.path.segments, path.segments)
    if !should_drop {
      kept.push(entry)
    }
  }
  { entries: kept }
}

///|
fn state_kill_roots(state : TaintState, roots : Array[String]) -> TaintState {
  let kept : Array[StateEntry] = []
  for entry in state.entries {
    if !roots.contains(entry.path.root) {
      kept.push(entry)
    }
  }
  { entries: kept }
}

///|
fn state_keep_roots(state : TaintState, roots : Array[String]) -> TaintState {
  let kept : Array[StateEntry] = []
  for entry in state.entries {
    if roots.contains(entry.path.root) {
      merge_state_entry(kept, entry.path, entry.origins)
    }
  }
  { entries: kept }
}

///|
/// Restore selected roots from a baseline state.
///
/// Scoped binders created by patterns should not leak back into outer scope.
fn state_restore_roots(
  state : TaintState,
  roots : Array[String],
  baseline : TaintState,
) -> TaintState {
  if roots.is_empty() {
    return state
  }
  state_merge(state_kill_roots(state, roots), state_keep_roots(baseline, roots))
}

///|
/// Overwrite an absolute path with the incoming relative taint tree.
///
/// A whole-variable assignment kills the whole root subtree. A field/index
/// assignment kills only that descendant subtree.
fn state_write_path(
  state : TaintState,
  path : StoragePath,
  value : TaintTree,
) -> TaintState {
  let killed = state_kill_path(state, path)
  let entries : Array[StateEntry] = []
  for entry in killed.entries {
    entries.push(entry)
  }
  for entry in value {
    merge_state_entry(
      entries,
      { root: path.root, segments: append_segments(path.segments, entry.path) },
      entry.origins,
    )
  }
  { entries, }
}

///|
/// Join branch states by unioning taint facts.
fn state_merge(left : TaintState, right : TaintState) -> TaintState {
  let entries : Array[StateEntry] = []
  for entry in left.entries {
    merge_state_entry(entries, entry.path, entry.origins)
  }
  for entry in right.entries {
    merge_state_entry(entries, entry.path, entry.origins)
  }
  { entries, }
}

///|
fn state_merge_all(states : Array[TaintState]) -> TaintState {
  let mut merged = empty_state()
  for state in states {
    merged = state_merge(merged, state)
  }
  merged
}

///|
fn same_origin_list(
  left : Array[TaintOrigin],
  right : Array[TaintOrigin],
) -> Bool {
  if left.length() != right.length() {
    return false
  }
  for origin in left {
    if !right.contains(origin) {
      return false
    }
  }
  true
}

///|
/// Equality up to entry ordering.
///
/// Fixpoint loops use this instead of structural equality because merge order
/// can differ between iterations.
fn state_equiv(left : TaintState, right : TaintState) -> Bool {
  if left.entries.length() != right.entries.length() {
    return false
  }
  for entry in left.entries {
    let mut found = false
    for other in right.entries {
      if storage_path_key(entry.path) == storage_path_key(other.path) &&
        same_origin_list(entry.origins, other.origins) {
        found = true
        break
      }
    }
    if !found {
      return false
    }
  }
  true
}

///|
/// Bind every variable introduced by `pattern` to the matching part of `value`.
///
/// Existing roots with the same names are removed first so inner binders shadow
/// outer variables instead of merging with them.
fn bind_pattern_to_state(
  state : TaintState,
  pattern : Json,
  value : TaintTree,
) -> TaintState {
  let bindings = pattern_bindings(pattern, value)
  if bindings.is_empty() {
    return state
  }
  let names : Array[String] = []
  for binding in bindings {
    if !names.contains(binding.name) {
      names.push(binding.name)
    }
  }
  let mut next = state_kill_roots(state, names)
  for binding in bindings {
    next = state_write_path(next, storage_path(binding.name), binding.value)
  }
  next
}

///|
/// Prefer precise structural destructuring and fall back to copying the whole
/// value to every binder when the pattern is too complex for v1.
fn pattern_bindings(pattern : Json, value : TaintTree) -> Array[PatternBinding] {
  match precise_pattern_bindings(pattern, value) {
    Some(bindings) => bindings
    None => {
      let names = collect_pattern_binder_names(pattern)
      let bindings : Array[PatternBinding] = []
      for name in names {
        bindings.push({ name, value: copy_tree(value) })
      }
      bindings
    }
  }
}

///|
/// Constructor patterns are transparent to taint shape in v1.
///
/// The taint domain does not encode constructor tags as path segments, so a
/// unary constructor such as `Some(pat)` refines the payload directly. Multi-
/// argument constructors fall back to tuple-slot projection.
fn precise_constructor_pattern_bindings(
  args : Json,
  value : TaintTree,
) -> Array[PatternBinding]? {
  match args {
    Null => Some([])
    { "kind": "Pattern::Constr::ArgList", "children": Array(items), .. } => {
      if items.is_empty() {
        return Some([])
      }
      if items.length() == 1 {
        match items[0] {
          {
            "kind": "ConstrPatArg",
            "children": {
              "pat": child_pattern,
              "kind": { "kind": "ArgumentKind::Positional", .. },
              ..
            },
            ..
          } => return precise_pattern_bindings(child_pattern, value)
          _ => return None
        }
      }
      let bindings : Array[PatternBinding] = []
      for index in 0..<items.length() {
        match items[index] {
          {
            "kind": "ConstrPatArg",
            "children": {
              "pat": child_pattern,
              "kind": { "kind": "ArgumentKind::Positional", .. },
              ..
            },
            ..
          } =>
            match
              precise_pattern_bindings(
                child_pattern,
                tree_project(value, [PathSegment::TupleIndex(index)]),
              ) {
              Some(child_bindings) =>
                for binding in child_bindings {
                  bindings.push(binding)
                }
              None => return None
            }
          _ => return None
        }
      }
      Some(bindings)
    }
    _ => None
  }
}

///|
/// Best-effort structural destructuring for tuple/record/fixed-array patterns.
///
/// Returning `None` means the caller should use the conservative fallback where
/// every bound name receives the whole incoming value taint.
fn precise_pattern_bindings(
  pattern : Json,
  value : TaintTree,
) -> Array[PatternBinding]? {
  match pattern {
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
    } => Some([{ name, value: copy_tree(value) }])
    { "kind": "Pattern::Constr", "children": { "args": args, .. }, .. } =>
      precise_constructor_pattern_bindings(args, value)
    {
      "kind": "Pattern::Tuple",
      "children": {
        "pats": {
          "kind": "Pattern::Tuple::PatternList",
          "children": Array(items),
          ..
        },
        ..
      },
      ..
    } => {
      let bindings : Array[PatternBinding] = []
      for index in 0..<items.length() {
        match
          precise_pattern_bindings(
            items[index],
            tree_project(value, [PathSegment::TupleIndex(index)]),
          ) {
          Some(child_bindings) =>
            for binding in child_bindings {
              bindings.push(binding)
            }
          None => return None
        }
      }
      Some(bindings)
    }
    {
      "kind": "Pattern::Record",
      "children": {
        "fields": {
          "kind": "Pattern::Record::FieldList",
          "children": Array(fields),
          ..
        },
        ..
      },
      ..
    } => {
      let bindings : Array[PatternBinding] = []
      for field in fields {
        match field {
          {
            "kind": "FieldPat",
            "children": {
              "label": {
                "kind": "Label",
                "children": { "name": String(name), .. },
                ..
              },
              "pattern": child_pattern,
              ..
            },
            ..
          } =>
            match
              precise_pattern_bindings(
                child_pattern,
                tree_project(value, [PathSegment::Field(name)]),
              ) {
              Some(child_bindings) =>
                for binding in child_bindings {
                  bindings.push(binding)
                }
              None => return None
            }
          _ => return None
        }
      }
      Some(bindings)
    }
    {
      "kind": "Pattern::Array",
      "children": {
        "pats": {
          "kind": "ArrayPatterns::Closed",
          "children": {
            "value": {
              "kind": "ArrayPatterns::Closed::PatternList",
              "children": Array(items),
              ..
            },
            ..
          },
          ..
        },
        ..
      },
      ..
    } => {
      let bindings : Array[PatternBinding] = []
      for index in 0..<items.length() {
        match items[index] {
          {
            "kind": "ArrayPattern::Pattern",
            "children": { "value": child_pattern, .. },
            ..
          } =>
            match
              precise_pattern_bindings(
                child_pattern,
                tree_project(value, [PathSegment::ConstIndex(index.to_string())]),
              ) {
              Some(child_bindings) =>
                for binding in child_bindings {
                  bindings.push(binding)
                }
              None => return None
            }
          _ => return None
        }
      }
      Some(bindings)
    }
    { "kind": "Pattern::Any", .. } => Some([])
    _ => None
  }
}

///|
/// Assemble a tuple value from the taint trees of its items.
fn tuple_tree(items : Array[TaintTree]) -> TaintTree {
  let merged : TaintTree = []
  for index in 0..<items.length() {
    let prefixed = tree_prefix(items[index], [PathSegment::TupleIndex(index)])
    for entry in prefixed {
      merge_relative_entry(merged, entry.path, entry.origins)
    }
  }
  merged
}

///|
/// Read "the element type" from an array-like value.
///
/// Both precise constant indices and dynamic AnyIndex entries contribute to the
/// element view used by `foreach`.
fn collection_element_tree(value : TaintTree) -> TaintTree {
  let projected : TaintTree = []
  for entry in value {
    guard entry.path is [head, ..] else { continue }
    let rest : Array[PathSegment] = []
    for index in 1..<entry.path.length() {
      rest.push(entry.path[index])
    }
    match head {
      PathSegment::AnyIndex | PathSegment::ConstIndex(_) =>
        merge_relative_entry(projected, rest, entry.origins)
      _ => ()
    }
  }
  projected
}
