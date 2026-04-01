///|
pub fn normalize_identifier_name(ast : Json) -> String? {
  match ast {
    { "kind": "Binder", "children": { "name": String(name), .. }, .. } =>
      Some(name)
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
    } => Some(name)
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
