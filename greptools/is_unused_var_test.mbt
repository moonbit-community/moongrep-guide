///|
test "normalize_identifier_name supports simple Var targets" {
  let ast : Json = {
    "kind": "Var",
    "children": {
      "name": { "kind": "LongIdent::Ident", "children": { "value": "target" } },
    },
  }
  assert_true(normalize_identifier_name(ast) == Some("target"))
}

///|
test "normalize_identifier_name rejects qualified Var targets" {
  let ast : Json = {
    "kind": "Var",
    "children": {
      "name": {
        "kind": "LongIdent::Dot",
        "children": { "pkg": "nav", "id": "load" },
      },
    },
  }
  assert_true(normalize_identifier_name(ast) is None)
}
