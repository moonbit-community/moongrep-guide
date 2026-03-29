///|
test "lang/cstyle-for-unused-loop-var: basic" {
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    println("foo")
    #|  }
    #|}
  let hits = []
  @greptools.traverse_top_impls(name="<memory>", source, context=hits, (
    hits,
    ast,
  ) => lang_cstyle_for_unused_loop_var("<memory>", ast, hits))
  assert_true(hits is [{ rule_id: "lang/cstyle-for-unused-loop-var", .. }])
}

///|
test "lang/cstyle-for-unused-loop-var: if + is" {
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    if foo is some(i) {
    #|      println(i)
    #|    }
    #|  }
    #|}
  let hits = []
  @greptools.traverse_top_impls(name="<memory>", source, context=hits, (
    hits,
    ast,
  ) => lang_cstyle_for_unused_loop_var("<memory>", ast, hits))
  // bug: is expression `foo is some(i)` in if condition should shadowing loop variable `i`
  assert_true(hits is [{ rule_id: "lang/cstyle-for-unused-loop-var", .. }])
  // if condition have is expression that shadowed loop variable 
  // but use loop variable in else branch
  let source =
    #|fn main {
    #|  for i = 0; i < 10; i = i + 1 {
    #|    if foo is some(i) {
    #|      println(i)
    #|    } else {
    #|      println(i)
    #|    }
    #|  }
    #|}
  let hits = []
  @greptools.traverse_top_impls(name="<memory>", source, context=hits, (
    hits,
    ast,
  ) => lang_cstyle_for_unused_loop_var("<memory>", ast, hits))
  assert_true(hits is [])
}
