///|
pub struct BundledTaintRule {
  rule_id : String
  package_name : String
  description : String
  sink_ids : Array[String]
  spec : @taint.TaintSpec
}

///|
fn copy_path_segments(
  segments : Array[@taint.PathSegment],
) -> Array[@taint.PathSegment] {
  let copied : Array[@taint.PathSegment] = []
  for segment in segments {
    copied.push(segment)
  }
  copied
}

///|
fn copy_taint_origins(
  origins : Array[@taint.TaintOrigin],
) -> Array[@taint.TaintOrigin] {
  let copied : Array[@taint.TaintOrigin] = []
  for origin in origins {
    copied.push(origin)
  }
  copied
}

///|
fn merge_origins_unique(
  left : Array[@taint.TaintOrigin],
  right : Array[@taint.TaintOrigin],
) -> Array[@taint.TaintOrigin] {
  let merged = copy_taint_origins(left)
  for origin in right {
    if !merged.contains(origin) {
      merged.push(origin)
    }
  }
  merged
}

///|
fn path_segments_key(segments : Array[@taint.PathSegment]) -> String {
  let rendered : Array[String] = []
  for segment in segments {
    rendered.push(segment.to_json().stringify())
  }
  rendered.join("/")
}

///|
fn taint_tree_origins(tree : @taint.TaintTree) -> Array[@taint.TaintOrigin] {
  let origins : Array[@taint.TaintOrigin] = []
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
fn merge_relative_entry(
  tree : @taint.TaintTree,
  path : Array[@taint.PathSegment],
  origins : Array[@taint.TaintOrigin],
) -> Unit {
  let key = path_segments_key(path)
  for index in 0..<tree.length() {
    if path_segments_key(tree[index].path) == key {
      tree[index] = {
        path: copy_path_segments(tree[index].path),
        origins: merge_origins_unique(tree[index].origins, origins),
      }
      return
    }
  }
  tree.push({
    path: copy_path_segments(path),
    origins: copy_taint_origins(origins),
  })
}

///|
fn merge_taint_tree_into(
  target : @taint.TaintTree,
  extra : @taint.TaintTree,
) -> Unit {
  for entry in extra {
    merge_relative_entry(target, entry.path, entry.origins)
  }
}

///|
fn add_storage_path_unique(
  paths : Array[@taint.StoragePath],
  path : @taint.StoragePath,
) -> Unit {
  if !paths.contains(path) {
    paths.push(path)
  }
}

///|
fn add_sink_finding_if_tainted(
  findings : Array[@taint.SinkFinding],
  rule_id : String,
  sink_id : String,
  sink_loc : Json,
  sink_site : @taint.ValueSite,
  taint : @taint.TaintTree,
) -> Unit {
  let origins = taint_tree_origins(taint)
  if origins.is_empty() {
    return
  }
  let finding : @taint.SinkFinding = {
    rule_id,
    sink_id,
    sink_loc,
    sink_site,
    origins,
  }
  if !findings.contains(finding) {
    findings.push(finding)
  }
}

///|
fn fresh_call_return_taint(
  info : @taint.CallInfo,
  rule_id : String,
  source_id : String,
) -> @taint.TaintTree {
  [
    {
      path: [],
      origins: [
        {
          rule_id,
          origin_id: source_id,
          site: @taint.ValueSite::CallResult(info.callee_name, info.loc),
          note: None,
        },
      ],
    },
  ]
}
