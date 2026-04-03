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
test "ast_json_repr_equal ignores loc fields" {
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
  assert_true(ast_json_repr_equal(lhs, rhs))
}

///|
test "ast_json_repr_equal rejects non-loc differences" {
  let lhs : Json = {
    "kind": "Expr::Field",
    "children": {
      "record": { "kind": "Expr::Ident", "children": {} },
      "accessor": {
        "kind": "Accessor::Label",
        "children": {
          "value": { "kind": "Label", "children": { "name": "count" } },
        },
      },
    },
  }
  let rhs : Json = {
    "kind": "Expr::Field",
    "children": {
      "record": { "kind": "Expr::Ident", "children": {} },
      "accessor": {
        "kind": "Accessor::Label",
        "children": {
          "value": { "kind": "Label", "children": { "name": "total" } },
        },
      },
    },
  }
  assert_false(ast_json_repr_equal(lhs, rhs))
}

///|
test "ast_json_repr_equal respects array order" {
  let lhs : Json = {
    "kind": "Expr::Tuple",
    "children": {
      "items": [
        { "kind": "Expr::Ident", "children": { "name": "lhs" } },
        { "kind": "Expr::Ident", "children": { "name": "rhs" } },
      ],
    },
  }
  let rhs : Json = {
    "kind": "Expr::Tuple",
    "children": {
      "items": [
        { "kind": "Expr::Ident", "children": { "name": "rhs" } },
        { "kind": "Expr::Ident", "children": { "name": "lhs" } },
      ],
    },
  }
  assert_false(ast_json_repr_equal(lhs, rhs))
}

///|
test "ast_json_repr_equal ignores object field order" {
  let lhs : Json = {
    "kind": "Expr::Apply",
    "children": {
      "func": { "kind": "Expr::Ident", "children": { "name": "load" } },
      "args": [{ "kind": "Argument", "children": { "value": "target" } }],
    },
  }
  let rhs : Json = {
    "children": {
      "args": [{ "kind": "Argument", "children": { "value": "target" } }],
      "func": { "kind": "Expr::Ident", "children": { "name": "load" } },
    },
    "kind": "Expr::Apply",
  }
  assert_true(ast_json_repr_equal(lhs, rhs))
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
