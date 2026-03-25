///|
struct SkippedFile {
  file : String
  reason : String
} derive(Eq)

///|
struct DirectoryScanResult {
  hits : Array[MatchHit]
  skipped_files : Array[SkippedFile]
} derive(Eq)

///|
fn render_skipped_file_message(skipped : SkippedFile) -> String {
  "warning: skipping \{skipped.file}: parse failed"
}

///|
fn compact_scan_error_message(err : String) -> String {
  err.replace_all(old="\n", new=" ").trim().to_string()
}

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
fn collect_directory_hits(scan_root : String) -> DirectoryScanResult raise {
  let files : Array[String] = []
  collect_source_files(scan_root, files)
  files.sort()
  let hits : Array[MatchHit] = []
  let skipped_files : Array[SkippedFile] = []
  for file in files {
    let source = @fs.read_file_to_string(file)
    find_rule_hits(name=file, source, hits) catch {
      Failure::Failure(err) =>
        skipped_files.push({ file, reason: compact_scan_error_message(err) })
      err => raise err
    }
  }
  { hits, skipped_files }
}
