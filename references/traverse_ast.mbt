///|
pub suberror AstTraverseError {
  InvalidNode(Json)
  InvalidChildren(Json)
}

///|
/// Walks a JSON AST in pre-order and visits each structural node.
///
/// The callback is invoked before children are traversed. Returning `false`
/// skips the current node's subtree; returning `true` continues recursively.
///
/// Raises `InvalidNode` or `InvalidChildren` when the JSON does not match the
/// expected MoonBit AST object shape.
pub fn[C] traverse_ast_json_repr(
  ast : Json,
  callback : (C, Json) -> Bool raise,
  context~ : C,
) -> Unit raise {
  match ast {
    Object({ "kind": _, "loc": _, "children": children, .. } as object) =>
      if object.length() == 3 {
        if !callback(context, ast) {
          return
        }
        match children {
          Object(children) =>
            for _, subtree in children.iter2() {
              traverse_ast_json_repr(subtree, callback, context~)
            }
          Array(children) =>
            for subtree in children {
              traverse_ast_json_repr(subtree, callback, context~)
            }
          children => raise InvalidChildren(children)
        }
      } else {
        raise InvalidNode(ast)
      }
    _ => ()
  }
}

///|
/// Parses `source` as a MoonBit program and traverses each top-level impl AST.
///
/// Each parsed top-level item is converted to JSON and then visited with
/// `traverse_ast_json_repr`, so the callback sees the same pre-order walk and
/// subtree-pruning behavior.
///
/// Parsing failures abort with the first formatted parser report.
pub fn[C] traverse_top_impls(
  name~ : String,
  source : String,
  callback : (C, Json) -> Bool raise,
  context~ : C,
) -> Unit raise {
  @basic.show_loc.val = Json
  let (program, reports) = @lexer.tokens_from_string(
      source,
      comment=true,
      name~,
    ).tokens
    |> @handrolled_parser.parse()
  if reports is [err, ..] {
    fail(err.to_json().stringify(indent=2))
  } else {
    for impl_ in program.iter().map(impl_ => impl_.json_repr()) {
      traverse_ast_json_repr(impl_, callback, context~)
    }
  }
}
