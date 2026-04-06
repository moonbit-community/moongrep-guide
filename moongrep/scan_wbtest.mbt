///|
fn reset_scan_test_dir(dir : String) -> Unit raise {
  let broken_file = "\{dir}/broken.mbt"
  let valid_file = "\{dir}/valid.mbt"
  if @fs.path_exists(broken_file) {
    @fs.remove_file(broken_file)
  }
  if @fs.path_exists(valid_file) {
    @fs.remove_file(valid_file)
  }
  if @fs.path_exists(dir) {
    @fs.remove_dir(dir)
  }
  @fs.create_dir(dir)
}

///|
test "collect directory hits skips files that fail to parse" {
  let dir = "temp"
  let broken_file = "\{dir}/broken.mbt"
  let valid_file = "\{dir}/valid.mbt"
  let valid_source =
    #|fn valid(limit : Int) -> Unit {
    #|  for i = 0; i < limit; i = i + 1 {
    #|    println("tick")
    #|  }
    #|}
  let broken_source =
    #|fn broken(limit : Int) -> Unit {
    #|  for i = 0; i < limit; i = {
    #|}
  reset_scan_test_dir(dir)
  @fs.write_string_to_file(valid_file, valid_source)
  @fs.write_string_to_file(broken_file, broken_source)
  let result = collect_directory_hits(dir)
  assert_true(result.hits.length() == 1)
  inspect(result.hits[0].file, content=valid_file)
  inspect(result.hits[0].rule_id, content="language/cstyle-for-unused-loop-var")
  assert_true(result.skipped_files.length() == 1)
  inspect(result.skipped_files[0].file, content=broken_file)
  assert_true(result.skipped_files[0].reason != "")
  assert_true(
    render_skipped_file_message(result.skipped_files[0]).contains(
      "warning: skipping temp/broken.mbt: parse failed",
    ),
  )
  @fs.remove_file(broken_file)
  @fs.remove_file(valid_file)
  @fs.remove_dir(dir)
}

///|
test "collect directory hits ignores loops with non-`<` conditions" {
  let dir = "_build/moongrep-scan-test-non-cstyle-condition"
  let valid_file = "\{dir}/valid.mbt"
  let source =
    #|fn valid(a : Int) -> Unit {
    #|  for i = 0; a.local_get(i) is Some(x); i = i + 1 {
    #|    println(x)
    #|  }
    #|}
  reset_scan_test_dir(dir)
  @fs.write_string_to_file(valid_file, source)
  let result = collect_directory_hits(dir)
  assert_true(result.hits.is_empty())
  assert_true(result.skipped_files.is_empty())
  @fs.remove_file(valid_file)
  @fs.remove_dir(dir)
}

///|
fn taint_hits(hits : Array[@greptools.MatchHit]) -> Array[@greptools.MatchHit] {
  let filtered : Array[@greptools.MatchHit] = []
  for hit in hits {
    if hit.rule_id == "test/taint-basic" {
      filtered.push(hit)
    }
  }
  filtered
}

///|
test "collect directory hits reports bundled taint findings" {
  let dir = "_build/moongrep-scan-test-taint-hit"
  let valid_file = "\{dir}/valid.mbt"
  let source =
    #|fn valid() -> Unit {
    #|  let value = __test_taint_source()
    #|  __test_taint_sink(value)
    #|}
  reset_scan_test_dir(dir)
  @fs.write_string_to_file(valid_file, source)
  let result = collect_directory_hits(dir)
  let hits = taint_hits(result.hits)
  assert_true(result.skipped_files.is_empty())
  assert_eq(hits.length(), 1)
  inspect(hits[0].file, content=valid_file)
  inspect(hits[0].rule_id, content="test/taint-basic")
  assert_eq(hits[0].pattern_index, 0)
  @fs.remove_file(valid_file)
  @fs.remove_dir(dir)
}

///|
test "collect directory hits respects bundled taint sanitizers" {
  let dir = "_build/moongrep-scan-test-taint-sanitizer"
  let valid_file = "\{dir}/valid.mbt"
  let source =
    #|fn valid() -> Unit {
    #|  let value = __test_taint_source()
    #|  __test_taint_sanitize(value)
    #|  __test_taint_sink(value)
    #|}
  reset_scan_test_dir(dir)
  @fs.write_string_to_file(valid_file, source)
  let result = collect_directory_hits(dir)
  assert_true(result.skipped_files.is_empty())
  assert_true(taint_hits(result.hits).is_empty())
  @fs.remove_file(valid_file)
  @fs.remove_dir(dir)
}
