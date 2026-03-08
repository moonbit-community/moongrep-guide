///|
// Pattern assets:
// - references/patterns/c99style_for_loop.pattern.mbt
// - references/patterns/c99style_for_loop.pattern.json
fn identify_c99style_for_loop(
  source : String,
  name~ : String,
  locations : Array[Json],
) -> Unit raise {
  // pattern:
  // for $COUNT = $N; $COUNT < $ARRAY.length(); $COUNT = $COUNT + 1 {
  //   $BODY
  // }

  traverse_top_impls(name~, source, ast => {
    match ast {
      {
        "kind": "Expr::For",
        "loc": loc,
        "children": {
          "binders": {
            "kind": "Expr::For::BindingList",
            "children": [
              {
                "kind": "For::Binding",
                "children": {
                  "binder": {
                    "kind": "Binder",
                    "children": { "name": count_1, .. },
                    ..
                  },
                  "expr": start_idx,
                  ..
                },
                ..
              },
            ],
            ..
          },
          "condition": {
            "kind": "Expr::Infix",
            "children": {
              "op": {
                "kind": "Var",
                "children": {
                  "name": {
                    "kind": "LongIdent::Ident",
                    "children": { "value": "<", .. },
                    ..
                  },
                  ..
                },
                ..
              },
              "lhs": {
                "kind": "Expr::Ident",
                "children": {
                  "id": {
                    "kind": "Var",
                    "children": {
                      "name": {
                        "kind": "LongIdent::Ident",
                        "children": { "value": count_2, .. },
                        ..
                      },
                      ..
                    },
                    ..
                  },
                  ..
                },
                ..
              },
              "rhs": {
                "kind": "Expr::DotApply",
                "children": {
                  "self": {
                    "kind": "Expr::Ident",
                    "children": {
                      "id": {
                        "kind": "Var",
                        "children": {
                          "name": {
                            "kind": "LongIdent::Ident",
                            "children": { "value": String(array_name), .. },
                            ..
                          },
                          ..
                        },
                        ..
                      },
                      ..
                    },
                    ..
                  },
                  "method_name": {
                    "kind": "Label",
                    "children": { "name": "length", .. },
                    ..
                  },
                  "args": {
                    "kind": "Expr::DotApply::ArgList",
                    "children": [],
                    ..
                  },
                  "return_self": false,
                  "attr": {
                    "kind": "ApplyAttr::NoAttr",
                    "children": { .. },
                    ..
                  },
                  ..
                },
                ..
              },
              ..
            },
            ..
          },
          "continue_block": {
            "kind": "Expr::For::ContBindingList",
            "children": [
              {
                "kind": "For::ContBinding",
                "children": {
                  "binder": {
                    "kind": "Binder",
                    "children": { "name": count_3, .. },
                    ..
                  },
                  "expr": {
                    "kind": "Expr::Infix",
                    "children": {
                      "op": {
                        "kind": "Var",
                        "children": {
                          "name": {
                            "kind": "LongIdent::Ident",
                            "children": { "value": "+", .. },
                            ..
                          },
                          ..
                        },
                        ..
                      },
                      "lhs": {
                        "kind": "Expr::Ident",
                        "children": {
                          "id": {
                            "kind": "Var",
                            "children": {
                              "name": {
                                "kind": "LongIdent::Ident",
                                "children": { "value": count_4, .. },
                                ..
                              },
                              ..
                            },
                            ..
                          },
                          ..
                        },
                        ..
                      },
                      "rhs": {
                        "kind": "Expr::Constant",
                        "children": {
                          "constant": {
                            "kind": "Constant::Int",
                            "children": { "value": "1", .. },
                            ..
                          },
                          ..
                        },
                        ..
                      },
                      ..
                    },
                    ..
                  },
                  ..
                },
                ..
              },
            ],
            ..
          },
          "body": body,
          "for_else": Null,
          "where_clause": Null,
          "label": Null,
          ..
        },
        ..
      } => {
        ignore(array_name)
        ignore(start_idx)
        ignore(body)
        if count_1 == count_2 && count_2 == count_3 && count_3 == count_4 {
          locations.push(loc)
        }
        true
      }
      _ => true
    }
  })
}

///|
// Pattern assets:
// - references/patterns/match_option_some_none.pattern.mbt
// - references/patterns/match_option_some_none.pattern.json
fn identify_match_option_some_none(
  name~ : String,
  source : String,
  locations : Array[Json],
) -> Unit raise {
  // pattern:
  //
  // match $VALUE {
  //   Some($ITEM) => $SOME_BODY
  //   None => $NONE_BODY
  // }
  //
  // or:
  //
  // match $VALUE {
  //   None => $NONE_BODY
  //   Some($ITEM) => $SOME_BODY
  // }
  fn is_option_some_case(ast : Json) -> Bool {
    match ast {
      {
        "kind": "Case",
        "children": {
          "pattern": {
            "kind": "Pattern::Constr",
            "children": {
              "constr": {
                "kind": "Constructor",
                "children": {
                  "name": {
                    "kind": "ConstrName",
                    "children": { "name": "Some", .. },
                    ..
                  },
                  ..
                },
                ..
              },
              "args": {
                "kind": "Pattern::Constr::ArgList",
                "children": [
                  {
                    "kind": "ConstrPatArg",
                    "children": {
                      "pat": pat,
                      "kind": {
                        "kind": "ArgumentKind::Positional",
                        "children": { .. },
                        ..
                      },
                      ..
                    },
                    ..
                  },
                ],
                ..
              },
              "is_open": false,
              ..
            },
            ..
          },
          "guard": Null,
          "body": body,
          ..
        },
        ..
      } => {
        ignore(pat)
        ignore(body)
        true
      }
      _ => false
    }
  }

  fn is_option_none_case(ast : Json) -> Bool {
    match ast {
      {
        "kind": "Case",
        "children": {
          "pattern": {
            "kind": "Pattern::Constr",
            "children": {
              "constr": {
                "kind": "Constructor",
                "children": {
                  "name": {
                    "kind": "ConstrName",
                    "children": { "name": "None", .. },
                    ..
                  },
                  ..
                },
                ..
              },
              "args": Null,
              "is_open": false,
              ..
            },
            ..
          },
          "guard": Null,
          "body": body,
          ..
        },
        ..
      } => {
        ignore(body)
        true
      }
      _ => false
    }
  }

  traverse_top_impls(name~, source, ast => {
    match ast {
      {
        "kind": "Expr::Match",
        "loc": loc,
        "children": {
          "expr": expr,
          "cases": {
            "kind": "Expr::Match::CaseList",
            "children": [case_1, case_2],
            ..
          },
          ..
        },
        ..
      } => {
        ignore(expr)
        if (is_option_some_case(case_1) && is_option_none_case(case_2)) ||
          (is_option_none_case(case_1) && is_option_some_case(case_2)) {
          locations.push(loc)
        }
        true
      }
      _ => true
    }
  })
}

///|
// Pattern assets:
// - references/patterns/array_push_call.pattern.mbt
// - references/patterns/array_push_call.pattern.json
fn identify_array_push_call(
  name~ : String,
  source : String,
  locations : Array[Json],
) -> Unit raise {
  // pattern:
  // $ARRAY.push($VALUE)
  traverse_top_impls(name~, source, ast => {
    match ast {
      {
        "kind": "Expr::DotApply",
        "loc": loc,
        "children": {
          "self": self_expr,
          "method_name": {
            "kind": "Label",
            "children": { "name": "push", .. },
            ..
          },
          "args": {
            "kind": "Expr::DotApply::ArgList",
            "children": [
              {
                "kind": "Argument",
                "children": {
                  "value": arg,
                  "kind": {
                    "kind": "ArgumentKind::Positional",
                    "children": { .. },
                    ..
                  },
                  ..
                },
                ..
              },
            ],
            ..
          },
          ..
        },
        ..
      } => {
        ignore(self_expr)
        ignore(arg)
        locations.push(loc)
        true
      }
      _ => true
    }
  })
}

///|
test {
  let program =
    #|fn foo(arr : Array[Int]) -> Unit {
    #|
    #| for i in 0..<10 {
    #|   println(i)
    #| }
    #|
    #| for i = 0; i < arr.length(); i = i + 1 {
    #|   println(arr[i])
    #| }
    #|
    #| // not typical c99 style forloop that can be replace with for in
    #| for j = 0; j < arr.length(); j = j + 2 {
    #|   println(arr[j])
    #| }
    #|
    #|}
  let locations = []
  identify_c99style_for_loop(name="foo", program, locations)
  json_inspect(locations, content=[
    {
      "file": "foo",
      "start": { "line": 7, "column": 2 },
      "end": { "line": 9, "column": 3 },
    },
  ])
}

///|
test {
  let program =
    #|fn foo(arr : Array[Int]) -> Unit {
    #|
    #| let other = [4, 5]
    #|
    #| for i = 0; i < arr.length(); i = i + 1 {
    #|   println(arr[i])
    #| }
    #|
    #| if true {
    #|   for j = 1; j < other.length(); j = j + 1 {
    #|     println(other[j])
    #|   }
    #| }
    #|
    #|}
  let locations = []
  identify_c99style_for_loop(name="nested", program, locations)
  json_inspect(locations, content=[
    {
      "file": "nested",
      "start": { "line": 5, "column": 2 },
      "end": { "line": 7, "column": 3 },
    },
    {
      "file": "nested",
      "start": { "line": 10, "column": 4 },
      "end": { "line": 12, "column": 5 },
    },
  ])
}

///|
test {
  let program =
    #|fn foo(arr : Array[Int]) -> Unit {
    #|
    #| for i in 0..<10 {
    #|   println(i)
    #| }
    #|
    #| for i = 0; i <= arr.length(); i = i + 1 {
    #|   println(arr[i])
    #| }
    #|
    #| for i = 0; i < arr.length(); i = i + 2 {
    #|   println(arr[i])
    #| }
    #|
    #| for i = 0; i < arr.length() - 1; i = i + 1 {
    #|   println(arr[i])
    #| }
    #|
    #|}
  let locations = []
  identify_c99style_for_loop(name="non_match", program, locations)
  json_inspect(locations, content=[])
}

///|
test {
  let program =
    #|fn foo(x : Int?, y : Int?, z : Result[Int, String]) -> Unit {
    #|
    #| let _ = match x {
    #|   Some(v) => v
    #|   None => 0
    #| }
    #|
    #| let _ = match y {
    #|   None => 1
    #|   Some(v) => v + 1
    #| }
    #|
    #| let _ = match z {
    #|   Ok(v) => v
    #|   Err(_) => 0
    #| }
    #|}
  let locations = []
  identify_match_option_some_none(name="match_option", program, locations)
  json_inspect(locations, content=[
    {
      "file": "match_option",
      "start": { "line": 3, "column": 10 },
      "end": { "line": 6, "column": 3 },
    },
    {
      "file": "match_option",
      "start": { "line": 8, "column": 10 },
      "end": { "line": 11, "column": 3 },
    },
  ])
}

///|
test {
  let program =
    #|fn foo(arr : Array[Int], other : Array[Int], nested : Array[Array[Int]]) -> Unit {
    #|
    #| arr.push(1)
    #| arr.push(2)
    #| arr.pop()
    #|
    #| other.push(4)
    #|
    #| nested[0].push(3)
    #|}
  let locations = []
  identify_array_push_call(name="array_push", program, locations)
  json_inspect(locations, content=[
    {
      "file": "array_push",
      "start": { "line": 3, "column": 2 },
      "end": { "line": 3, "column": 13 },
    },
    {
      "file": "array_push",
      "start": { "line": 4, "column": 2 },
      "end": { "line": 4, "column": 13 },
    },
    {
      "file": "array_push",
      "start": { "line": 7, "column": 2 },
      "end": { "line": 7, "column": 15 },
    },
    {
      "file": "array_push",
      "start": { "line": 9, "column": 2 },
      "end": { "line": 9, "column": 19 },
    },
  ])
}
