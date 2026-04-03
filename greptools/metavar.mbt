///|
/// Returns whether two AST JSON subtrees are structurally equal.
///
/// The comparison ignores every object field named `loc`, recursively compares
/// object children by key, and preserves array element order.
///
/// This is intended for comparing MoonBit AST fragments while ignoring source
/// locations. It is not a general-purpose JSON equivalence relation.
pub fn ast_json_repr_equal(lhs : Json, rhs : Json) -> Bool {
  match (lhs, rhs) {
    (Object(lhs_entries), Object(rhs_entries)) =>
      ast_json_repr_equal_object(lhs_entries, rhs_entries)
    (Array(lhs_items), Array(rhs_items)) =>
      ast_json_repr_equal_array(lhs_items, rhs_items)
    _ => lhs == rhs
  }
}

///|
fn ast_json_repr_equal_object(
  lhs_entries : Map[String, Json],
  rhs_entries : Map[String, Json],
) -> Bool {
  if ast_json_repr_field_count(lhs_entries) !=
    ast_json_repr_field_count(rhs_entries) {
    return false
  }
  for key, lhs_value in lhs_entries.iter2() {
    if key != "loc" {
      match rhs_entries.get(key) {
        Some(rhs_value) =>
          if !ast_json_repr_equal(lhs_value, rhs_value) {
            return false
          }
        None => return false
      }
    }
  }
  true
}

///|
fn ast_json_repr_equal_array(
  lhs_items : Array[Json],
  rhs_items : Array[Json],
) -> Bool {
  if lhs_items.length() != rhs_items.length() {
    return false
  }
  for index in 0..<lhs_items.length() {
    if !ast_json_repr_equal(lhs_items[index], rhs_items[index]) {
      return false
    }
  }
  true
}

///|
fn ast_json_repr_field_count(entries : Map[String, Json]) -> Int {
  let mut count = 0
  for key, _ in entries.iter2() {
    if key != "loc" {
      count = count + 1
    }
  }
  count
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
