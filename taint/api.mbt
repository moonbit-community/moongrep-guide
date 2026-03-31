// Public entrypoints for the intra-procedural taint engine.
//
// The data model is split across:
// - `api_paths.mbt`: precise state paths
// - `api_sites.mbt`: provenance / sink sites
// - `api_models.mbt`: taint trees, call models, and rule specs

///|
/// Raised when the caller passes an AST node that is not a supported
/// top-level function-like form.
pub suberror TaintAnalysisError {
  UnsupportedFunctionLike(Json)
} derive(Show)

///|
/// Collect supported top-level function-like AST nodes from one source file.
fn collect_function_like_nodes(
  name~ : String,
  source : String,
) -> Array[Json] raise {
  let nodes : Array[Json] = []
  @greptools.traverse_top_impls(name~, source, context=nodes, (nodes, ast) => {
    match ast {
      { "kind": "Impl::TopFuncDef", .. } | { "kind": "Impl::TopImpl", .. } => {
        nodes.push(ast)
        false
      }
      _ => true
    }
  })
  nodes
}

///|
/// Analyze one already-parsed top-level function-like AST node.
///
/// Supported nodes are `Impl::TopFuncDef` and `Impl::TopImpl`, normalized by
/// `extract_function_like_info` in `ast_path.mbt`. The returned findings belong
/// to this function only.
pub fn analyze_function_like_json(
  ast : Json,
  spec : TaintSpec,
) -> AnalysisResult raise {
  analyze_function_like_json_impl(ast, spec)
}

///|
/// Analyze one function-like AST node against multiple taint rules.
///
/// Each returned item represents one `(rule, function)` analysis pair and
/// carries the originating `rule_id`.
pub fn analyze_function_like_json_multi(
  ast : Json,
  rules : Array[TaintSpec],
) -> Array[AnalysisResult] raise {
  let results : Array[AnalysisResult] = []
  for rule in rules {
    results.push(analyze_function_like_json_impl(ast, rule))
  }
  results
}

///|
/// Parse a source file, extract supported top-level functions and impl methods,
/// and analyze each one independently with the same `TaintSpec`.
pub fn analyze_source_functions(
  name~ : String,
  source : String,
  spec : TaintSpec,
) -> Array[AnalysisResult] raise {
  let nodes = collect_function_like_nodes(name~, source)
  let results : Array[AnalysisResult] = []
  for node in nodes {
    results.push(analyze_function_like_json_impl(node, spec))
  }
  results
}

///|
/// Parse a source file once and analyze each extracted function-like node
/// against each taint rule independently.
///
/// Results are returned as a flat array of `(rule, function)` analysis pairs.
pub fn analyze_source_functions_multi(
  name~ : String,
  source : String,
  rules : Array[TaintSpec],
) -> Array[AnalysisResult] raise {
  let nodes = collect_function_like_nodes(name~, source)
  let results : Array[AnalysisResult] = []
  for node in nodes {
    for rule in rules {
      results.push(analyze_function_like_json_impl(node, rule))
    }
  }
  results
}
