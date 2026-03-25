///|
fn should_skip_scan_dir(name : String) -> Bool {
  name == ".git" || name == "_build" || name == ".mooncakes" || name == "target"
}

///|
fn collect_source_files(dir : String, files : Array[String]) -> Unit raise {
  let entries = @fs.read_dir(dir)
  entries.sort()
  for entry in entries {
    if !should_skip_scan_dir(entry) {
      let path = "\{dir}/\{entry}"
      if @fs.is_dir(path) {
        collect_source_files(path, files)
      } else if path.has_suffix(".mbt") {
        files.push(path)
      }
    }
  }
}

///|
fn find_rule_hits(
  name~ : String,
  source : String,
  hits : Array[MatchHit],
) -> Unit raise {
  @references.traverse_top_impls(name~, source, context=hits, (hits, ast) => {
    apply_bundled_rules(name, ast, hits)
  })
}

///|
fn collect_directory_hits(scan_root : String) -> Array[MatchHit] raise {
  let files : Array[String] = []
  collect_source_files(scan_root, files)
  files.sort()
  let hits : Array[MatchHit] = []
  for file in files {
    let source = @fs.read_file_to_string(file)
    find_rule_hits(name=file, source, hits)
  }
  hits
}
