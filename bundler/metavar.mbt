///|
fn recognize_metavar(node : Json, ctx : PatternEmitContext) -> String? {
  match node {
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
    } if ctx.declared_metavars.contains(name) => Some(record_binding(ctx, name))
    {
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
    } if ctx.declared_metavars.contains(name) => Some(record_binding(ctx, name))
    { "kind": "Binder", "children": { "name": String(name), .. }, .. } if ctx.declared_metavars.contains(
        name,
      ) => Some(record_binding(ctx, name))
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
    } if ctx.declared_metavars.contains(name) => Some(record_binding(ctx, name))
    _ => None
  }
}
