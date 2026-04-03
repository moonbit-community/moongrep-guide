///|
/// Returns a stable string form for structural AST comparisons.
///
/// The normalization drops every object field named `loc`, sorts object keys,
/// and recursively normalizes child values. Array element order is preserved.
///
/// This is intended for comparing MoonBit AST fragments while ignoring source
/// locations. It is not a general-purpose JSON canonicalization function.
pub fn normalize_structural_json(ast : Json) -> String {
  match ast {
    Object(entries) => {
      let keys : Array[String] = []
      for key, _ in entries.iter2() {
        if key != "loc" {
          keys.push(key)
        }
      }
      keys.sort()
      let builder = StringBuilder::new()
      builder.write_char('{')
      for index in 0..<keys.length() {
        if index != 0 {
          builder.write_char(',')
        }
        let key = keys[index]
        builder.write_string(Json::string(key).stringify())
        builder.write_char(':')
        builder.write_string(
          normalize_structural_json(entries.get(key).unwrap()),
        )
      }
      builder.write_char('}')
      builder.to_string()
    }
    Array(items) => {
      let builder = StringBuilder::new()
      builder.write_char('[')
      for index in 0..<items.length() {
        if index != 0 {
          builder.write_char(',')
        }
        builder.write_string(normalize_structural_json(items[index]))
      }
      builder.write_char(']')
      builder.to_string()
    }
    _ => ast.stringify()
  }
}

///|
/// Extracts a comparable identifier name from supported AST node shapes.
///
/// This recognizes `Binder`, `Label`, unqualified `Var`, `Expr::Ident`, and
/// `Pattern::Var` nodes, and returns the underlying name when present.
///
/// Returns `None` for unsupported node kinds and for qualified identifiers
/// such as `LongIdent::Dot`, where there is no single local name to compare.
pub fn normalize_identifier_name(ast : Json) -> String? {
  match ast {
    { "kind": "Binder", "children": { "name": String(name), .. }, .. } =>
      Some(name)
    { "kind": "Label", "children": { "name": String(name), .. }, .. } =>
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
