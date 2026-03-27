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
          ignore(upper_limit)
          match
            (
              normalize_metavar_name(init_var),
              normalize_metavar_name(cond_counter),
              normalize_metavar_name(cont_counter),
            ) {
            (Some(counter), Some(cond_name), Some(cont_name)) =>
              results.push(
                counter == cond_name &&
                counter == cont_name &&
                is_cstyle_for_with_unused_loop_var(counter, next, body),
              )
            _ => results.push(false)
          }
          true
        }
        _ => true
      }
    },
  )
  results
}

///|
fn collect_normalized_name(ast : Json, results : Array[String]) -> Bool {
  match normalize_metavar_name(ast) {
    Some(name) => results.push(name)
    None => ()
  }
  false
}

///|
fn collect_name_only_matches(source : String) -> Array[String] raise {
  let results : Array[String] = []
  @references.traverse_top_impls(
    name="rules/guard_helpers_test",
    source,
    context=results,
    (results, ast) => {
      match ast {
        { "kind": "Binder", .. } => collect_normalized_name(ast, results)
        { "kind": "Expr::Ident", .. } => collect_normalized_name(ast, results)
        { "kind": "Pattern::Var", .. } => collect_normalized_name(ast, results)
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
test "normalize_metavar_name extracts binder ident and pattern-var names" {
  let source =
    #|fn sample(limit : Int) -> Unit {
    #|  for i = 0; i < limit; i = i + 1 {
    #|    match value {
    #|      Some(item) => println(item)
    #|      None => ()
    #|    }
    #|  }
    #|}
  let results = collect_name_only_matches(source)
  assert_true(results.contains("i"))
  assert_true(results.contains("limit"))
  assert_true(results.contains("item"))
}

///|
test "normalize_metavar_name rejects non-name-like AST" {
  let source =
    #|fn sample(limit : Int) -> Unit {
    #|  for i = 0; i < limit; i = i + 1 {
    #|    println(i + 1)
    #|  }
    #|}
  let results : Array[Bool] = []
  @references.traverse_top_impls(
    name="rules/guard_helpers_test",
    source,
    context=results,
    (results, ast) => {
      match ast {
        { "kind": "Expr::Infix", .. } => {
          results.push(normalize_metavar_name(ast) is None)
          false
        }
        _ => true
      }
    },
  )
  assert_true(results.length() >= 1)
  assert_true(results[0])
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
