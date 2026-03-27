///|
pub fn normalize_metavar_name(ast : Json) -> String? {
  match ast {
    { "kind": "Binder", "children": { "name": String(name), .. }, .. } =>
      Some(name)
    {
      "kind": "Expr::Ident",
      "children": {
        "id": {
          "kind": "Var",
          "children": {
            "name": {
              "kind": "LongIdent::Ident",
              "children": { "value": String(name), .. },
              ..
            },
            ..
          },
          ..
        },
        ..
      },
      ..
    } => Some(name)
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
    } => Some(name)
    _ => None
  }
}

///|
pub fn contains_ident(ast : Json, name : String) -> Bool {
  let matches : Array[Unit] = []
  ignore(
    try? @references.traverse_ast_json_repr(ast, context=matches, (
      matches,
      node,
    ) => {
      match node {
        {
          "kind": "Expr::Ident",
          "children": {
            "id": {
              "kind": "Var",
              "children": {
                "name": {
                  "kind": "LongIdent::Ident",
                  "children": { "value": String(found), .. },
                  ..
                },
                ..
              },
              ..
            },
            ..
          },
          ..
        } if found == name => {
          matches.push(())
          false
        }
        {
          "kind": "InterpElem::Source",
          "children": { "source": String(source), .. },
          ..
        } if interp_source_contains_ident(source, name) => {
          matches.push(())
          false
        }
        _ => true
      }
    }),
  )
  !matches.is_empty()
}

///|
fn interp_source_contains_ident(source : String, name : String) -> Bool {
  (source.trim().to_string() == name ||
  contains_ident(dump_expr_json_repr(source), name)) catch {
    _ => false
  }
}
