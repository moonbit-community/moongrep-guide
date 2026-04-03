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
  inspect(
    render_skipped_file_message(result.skipped_files[0]),
    content="warning: skipping temp/broken.mbt: parse failed",
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
