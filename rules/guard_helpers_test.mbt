///|
fn collect_loop_checks(source : String) -> Array[Bool] raise {
  let results : Array[Bool] = []
  @references.traverse_top_impls(
    name="rules/guard_helpers_test",
    source,
    context=results,
    (results, ast) => {
      match ast {
        {
          "kind": "Expr::For",
          "children": {
            "binders": {
              "kind": "Expr::For::BindingList",
              "children": [
                {
                  "kind": "For::Binding",
                  "children": { "binder": init_var, .. },
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
                "lhs": cond_counter,
                "rhs": upper_limit,
                ..
              },
              ..
            },
            "continue_block": {
              "kind": "Expr::For::ContBindingList",
              "children": [
                {
                  "kind": "For::ContBinding",
                  "children": { "binder": cont_counter, "expr": next, .. },
                  ..
                },
              ],
              ..
            },
            "body": body,
            ..
          },
          ..
        } => {
          results.push(
            is_cstyle_for_with_unused_loop_var(
              init_var, cond_counter, upper_limit, cont_counter, next, body,
            ),
          )
          true
        }
        _ => true
      }
    },
  )
  results
}

///|
test "guard helper matches unused c-style for loop variable" {
  let source =
    #|fn sample(limit : Int) -> Unit {
    #|  for i = 0; i < limit; i = i + 1 {
    #|    println("tick")
    #|  }
    #|}
  let results = collect_loop_checks(source)
  assert_true(results.length() == 1)
  assert_true(results[0])
}

///|
test "guard helper rejects used c-style for loop variable" {
  let source =
    #|fn sample(limit : Int) -> Unit {
    #|  for i = 0; i < limit; i = i + 1 {
    #|    println(i)
    #|  }
    #|}
  let results = collect_loop_checks(source)
  assert_true(results.length() == 1)
  assert_false(results[0])
}

///|
test "guard helper rejects loop variable used in string interpolation" {
  let source =
    #|fn sample(id : Int) -> Unit {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    println("thread \{id}: \{i}")
    #|    ctx.suspend()
    #|  }
    #|}
  let results = collect_loop_checks(source)
  assert_true(results.length() == 1)
  assert_false(results[0])
}

///|
test "guard helper rejects mismatched loop control variables" {
  let source =
    #|fn sample(limit : Int) -> Unit {
    #|  for i = 0; j < limit; i = i + 1 {
    #|    println("tick")
    #|  }
    #|}
  let results = collect_loop_checks(source)
  assert_true(results.length() == 1)
  assert_false(results[0])
}
