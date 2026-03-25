///|
// Guard helper for rules that need to inspect loop-control AST fragments.
pub fn is_cstyle_for_with_unused_loop_var(
  counter : Json,
  cond_counter : Json,
  _upper_limit : Json,
  cont_counter : Json,
  next : Json,
  body : Json,
) -> Bool {
  match
    (binder_name(counter), ident_name(cond_counter), binder_name(cont_counter)) {
    (Some(loop_var), Some(cond_name), Some(cont_name)) =>
      loop_var == cond_name &&
      loop_var == cont_name &&
      contains_ident(next, loop_var) &&
      !contains_ident(body, loop_var)
    _ => false
  }
}

///|
fn binder_name(ast : Json) -> String? {
  match ast {
    { "kind": "Binder", "children": { "name": String(name), .. }, .. } =>
      Some(name)
    _ => None
  }
}

///|
fn ident_name(ast : Json) -> String? {
  match ast {
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
    _ => None
  }
}

///|
fn contains_ident(ast : Json, name : String) -> Bool {
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
  if source.trim().to_string() == name {
    return true
  }
  let parsed = try? parse_expr_json_repr(source)
  match parsed {
    Ok(ast) => contains_ident(ast, name)
    Err(_) => false
  }
}

///|
fn parse_expr_json_repr(expr : String) -> Json raise {
  let (expr, reports) = @lexer.tokens_from_string(
      expr,
      comment=true,
      name="interpolation source",
    ).tokens
    |> @handrolled_parser.parse_expr
  if reports.is_empty() {
    expr.json_repr()
  } else {
    fail(reports.to_json().stringify(indent=2))
  }
}
