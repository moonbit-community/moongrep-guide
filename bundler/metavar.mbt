///|
fn is_builtin_ignore_metavar_name(name : String) -> Bool {
  if name.length() < 2 {
    false
  } else {
    for ch in name.iter() {
      if ch != '_' {
        return false
      }
    }
    true
  }
}

///|
fn emit_builtin_or_declared_metavar(
  name : String,
  ctx : PatternEmitContext,
) -> String? {
  if is_builtin_ignore_metavar_name(name) {
    Some("_")
  } else if ctx.declared_metavars.contains(name) {
    Some(record_binding(ctx, name))
  } else {
    None
  }
}

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
    } => emit_builtin_or_declared_metavar(name, ctx)
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
    } => emit_builtin_or_declared_metavar(name, ctx)
    { "kind": "Binder", "children": { "name": String(name), .. }, .. } =>
      emit_builtin_or_declared_metavar(name, ctx)
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
    } => emit_builtin_or_declared_metavar(name, ctx)
    _ => None
  }
}
