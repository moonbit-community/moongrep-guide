///|
fn collect_hits(source : String) -> Array[MatchHit] raise {
  let hits = []
  @greptools.traverse_top_impls(name="<memory>", source, context=hits, (
    hits,
    ast,
  ) => language_cstyle_for_unused_loop_var("<memory>", ast, hits))
  hits
}

///|
fn assert_single_unused_loop_var_hit(source : String) -> Unit raise {
  let hits = collect_hits(source)
  assert_true(hits is [{ rule_id: "language/cstyle-for-unused-loop-var", .. }])
}

///|
fn assert_no_unused_loop_var_hit(source : String) -> Unit raise {
  let hits = collect_hits(source)
  assert_true(hits is [])
}

///|
fn collect_potential_augmented_mutate_hits(
  source : String,
) -> Array[MatchHit] raise {
  let hits = []
  @greptools.traverse_top_impls(name="<memory>", source, context=hits, (
    hits,
    ast,
  ) => language_potential_augmented_mutate("<memory>", ast, hits))
  hits
}

///|
fn assert_single_potential_augmented_mutate_hit(source : String) -> Unit raise {
  let hits = collect_potential_augmented_mutate_hits(source)
  assert_true(hits is [{ rule_id: "language/potential-augmented-mutate", .. }])
}

///|
fn assert_no_potential_augmented_mutate_hit(source : String) -> Unit raise {
  let hits = collect_potential_augmented_mutate_hits(source)
  assert_true(hits is [])
}

///|
test "language/cstyle-for-unused-loop-var: basic" {
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    println("foo")
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: upper limit uses counter" {
  let source =
    #|fn main(limit : Int) {
    #|  for i = 0; i < limit - i; i = i + 1 {
    #|    println("foo")
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: body uses counter" {
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    println(i)
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: let shadow" {
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    let i = 42
    #|    println(i)
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: let mut shadow" {
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    let mut i = 42
    #|    i = i + 1
    #|    println(i)
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: match case shadow" {
  let source =
    #|fn main(value : Int?) {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    match value {
    #|      Some(i) => println(i)
    #|      None => println("none")
    #|    }
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: match mixed shadow and outer use" {
  let source =
    #|fn main(value : Int?) {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    match value {
    #|      Some(i) => println(i)
    #|      None => println(i)
    #|    }
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: match guard shadow only" {
  let source =
    #|fn main(value : Int?) {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    match value {
    #|      Some(i) if i > 0 => println(i)
    #|      Some(_) => println(0)
    #|      None => println("none")
    #|    }
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: match guard shadow plus outer use in fallback" {
  let source =
    #|fn main(value : Int?) {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    match value {
    #|      Some(i) if i > 0 => println(i)
    #|      Some(_) => println(0)
    #|      None => println(i)
    #|    }
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: lambda parameter shadow in body" {
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    let f = fn(i : Int) { i + 1 }
    #|    println(f(0))
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: lambda captures outer counter in body" {
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    let f = fn(x : Int) { i + x }
    #|    println(f(0))
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: lambda parameter shadow in upper limit" {
  let source =
    #|fn main {
    #|  for i = 0; i < (fn(i : Int) -> Int { i + 10 })(0); i = i + 1 {
    #|    println("foo")
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: lambda captures outer counter in upper limit" {
  let source =
    #|fn main {
    #|  for i = 0; i < (fn(x : Int) -> Int { i + x + 10 })(1); i = i + 1 {
    #|    println("foo")
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: nested inner for shadows outer counter" {
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    for i = 0; i < 3; i = i + 1 {
    #|      println(i)
    #|    }
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: nested inner for plus outer use after inner loop" {
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    for i = 0; i < 3; i = i + 1 {
    #|      println(i)
    #|    }
    #|    println(i)
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: string interpolation uses outer counter" {
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    println("\{i}")
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: if + is" {
  // is expression `foo is Some(i)` in if condition should shadowing loop variable `i`
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    if foo is Some(i) {
    #|      println(i)
    #|    }
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
  // if condition have is expression that shadowed loop variable 
  // but use loop variable in else branch
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    if foo is Some(i) {
    #|      println(i)
    #|    } else {
    #|      println(i)
    #|    }
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: guard + is" {
  // is expression `foo is Some(i)` in guard condition should shadowing loop variable `i`
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    guard foo is Some(i) else {
    #|      continue
    #|    }
    #|    println(i)
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
  // is expression `foo is Some(i)` in guard condition should shadowing loop variable `i`
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    guard foo is Some(i)
    #|    println(i)
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
  // guard condition have is expression that shadowed loop variable 
  // but use loop variable after guard
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    guard foo is Some(i) else {
    #|      println(i)
    #|    }
    #|    println(i)
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
  // no shadow
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    guard i is 0
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: while + is" {
  // is expression `foo is Some(i)` in while condition should shadowing loop variable `i`
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    while foo is Some(i) {
    #|      println(i)
    #|    }
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
  // while condition have is expression that shadowed loop variable
  // but use loop variable after while body
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    while foo is Some(i) {
    #|      println(i)
    #|    }
    #|    println(i)
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: while + is + nobreak" {
  // nobreak branch does not use outer loop variable `i`
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    while foo is Some(i) {
    #|      println(i)
    #|    } nobreak {
    #|      println("done")
    #|    }
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
  // nobreak branch uses outer loop variable `i`
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    while foo is Some(i) {
    #|      println(i)
    #|    } nobreak {
    #|      println(i)
    #|    }
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
  // while condition shadowing should not leak into nobreak branch,
  // but nobreak can establish its own shadowing with `is`
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    while foo is Some(i) {
    #|      println(i)
    #|    } nobreak {
    #|      if bar is Some(i) {
    #|        println(i)
    #|      }
    #|    }
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
}

///|
test "language/cstyle-for-unused-loop-var: match guard + is" {
  // is expression `foo is Some(i)` in match guard condition should shadowing loop variable `i`
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    match foo {
    #|      foo if foo is Some(i) => println(i)
    #|      None => println("foo")
    #|    }
    #|  }
    #|}
  assert_single_unused_loop_var_hit(source)
  // guard condition have is expression that shadowed loop variable 
  // but use loop variable in `None` branch
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    match foo {
    #|      foo if foo is Some(i) => println(i)
    #|      None => println(i)
    #|    }
    #|  }
    #|}
  assert_no_unused_loop_var_hit(source)
}

///|
test "language/potential-augmented-mutate: detects basic arithmetic updates" {
  let source =
    #|fn main {
    #|  let mut total = 0
    #|  total = total + 1
    #|}
  assert_single_potential_augmented_mutate_hit(source)
  let source =
    #|fn main {
    #|  let mut total = 0
    #|  total = 1 + total
    #|}
  assert_single_potential_augmented_mutate_hit(source)
  let source =
    #|fn main {
    #|  let mut total = 1
    #|  total = total * 2
    #|}
  assert_single_potential_augmented_mutate_hit(source)
  let source =
    #|fn main {
    #|  let mut total = 1
    #|  total = 2 * total
    #|}
  assert_single_potential_augmented_mutate_hit(source)
  let source =
    #|fn main {
    #|  let mut total = 3
    #|  total = total - 1
    #|}
  assert_single_potential_augmented_mutate_hit(source)
  let source =
    #|fn main {
    #|  let mut total = 8
    #|  total = total / 2
    #|}
  assert_single_potential_augmented_mutate_hit(source)
}

///|
test "language/potential-augmented-mutate: ignores nearby non-matches" {
  let source =
    #|fn main {
    #|  let mut total = 0
    #|  total += 1
    #|}
  assert_no_potential_augmented_mutate_hit(source)
  let source =
    #|fn main(other : Int) {
    #|  let mut total = 0
    #|  total = other + 1
    #|}
  assert_no_potential_augmented_mutate_hit(source)
  let source =
    #|fn main {
    #|  let mut total = 0
    #|  total = 1 - total
    #|}
  assert_no_potential_augmented_mutate_hit(source)
  let source =
    #|fn main {
    #|  let mut total = 1
    #|  total = 2 / total
    #|}
  assert_no_potential_augmented_mutate_hit(source)
}
