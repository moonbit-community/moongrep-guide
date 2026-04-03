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
test "normalize_structural_json ignores loc fields" {
  let lhs : Json = {
    "kind": "Expr::Field",
    "loc": { "line": 1 },
    "children": {
      "record": { "kind": "Expr::Ident", "loc": { "line": 1 }, "children": {} },
      "accessor": {
        "kind": "Accessor::Label",
        "loc": { "line": 1 },
        "children": {
          "value": {
            "kind": "Label",
            "loc": { "line": 1 },
            "children": { "name": "count" },
          },
        },
      },
    },
  }
  let rhs : Json = {
    "kind": "Expr::Field",
    "loc": { "line": 20 },
    "children": {
      "record": { "kind": "Expr::Ident", "loc": { "line": 20 }, "children": {} },
      "accessor": {
        "kind": "Accessor::Label",
        "loc": { "line": 20 },
        "children": {
          "value": {
            "kind": "Label",
            "loc": { "line": 20 },
            "children": { "name": "count" },
          },
        },
      },
    },
  }
  assert_true(normalize_structural_json(lhs) == normalize_structural_json(rhs))
}

///|
test "normalize_identifier_name supports Label nodes" {
  let ast : Json = { "kind": "Label", "children": { "name": "target" } }
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
