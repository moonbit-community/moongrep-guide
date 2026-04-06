///|
fn invalid_rule(path~ : String, info~ : String) -> @spec.RuleBundleError {
  @spec.invalid_rule(path~, info~)
}

///|
pub fn load_rules(rules_root : String) -> Array[@spec.RuleSpec] raise {
  let files = collect_rule_files(rules_root)
  if files.is_empty() {
    raise invalid_rule(path=rules_root, info="no YAML rule files found")
  }
  let rules : Array[@spec.RuleSpec] = []
  for file in files {
    let source = @fs.read_file_to_string(file)
    rules.push(parse_rule_source(file, rules_root, source))
  }
  rules
}

///|
fn collect_rule_files(rules_root : String) -> Array[String] raise {
  let files : Array[String] = []
  walk_rule_dir(rules_root, files)
  files.sort()
  files
}

///|
fn walk_rule_dir(dir : String, files : Array[String]) -> Unit raise {
  let entries = @fs.read_dir(dir)
  entries.sort()
  for entry in entries {
    let path = "\{dir}/\{entry}"
    if @fs.is_dir(path) {
      walk_rule_dir(path, files)
    } else if has_yaml_suffix(path) {
      files.push(path)
    }
  }
}

///|
fn has_yaml_suffix(path : String) -> Bool {
  path.has_suffix(".yaml") || path.has_suffix(".yml")
}

///|
fn parse_rule_source(
  path : String,
  rules_root : String,
  source : String,
) -> @spec.RuleSpec raise {
  let docs = @yaml.Yaml::load_from_string(source)
  if docs.length() != 1 {
    raise invalid_rule(
      path~,
      info="rule file must contain exactly one YAML document",
    )
  }
  guard docs[0] is @yaml.Yaml::Map(doc) else {
    raise invalid_rule(path~, info="top-level YAML document must be a mapping")
  }
  ensure_allowed_keys(path, "top-level rule", doc, [
    "package", "description", "patterns", "taint",
  ])
  let package_name = expect_yaml_string(doc, path, "package")
  let description = expect_description(doc, path)
  let definition = expect_rule_definition(doc, path)
  {
    rule_id: rule_id_from_path(path, rules_root),
    package_name,
    description,
    definition,
  }
}

///|
fn expect_rule_definition(
  doc : Map[String, @yaml.Yaml],
  path : String,
) -> @spec.RuleDefinitionSpec raise {
  let has_patterns = doc.contains("patterns")
  let has_taint = doc.contains("taint")
  if has_patterns == has_taint {
    raise invalid_rule(
      path~,
      info="rule must contain exactly one of patterns or taint",
    )
  }
  if has_patterns {
    let patterns = parse_rule_clause_array(
      expect_yaml_array(doc, path, "patterns"),
      path,
      "patterns",
      true,
      false,
    )
    @spec.RuleDefinitionSpec::Structural(patterns)
  } else {
    @spec.RuleDefinitionSpec::Taint(expect_taint_rule(doc, path))
  }
}

///|
fn expect_taint_rule(
  doc : Map[String, @yaml.Yaml],
  path : String,
) -> @spec.TaintRuleSpec raise {
  guard doc.get("taint") is Some(@yaml.Yaml::Map(taint_map)) else {
    raise invalid_rule(path~, info="taint must be a mapping")
  }
  ensure_allowed_keys(path, "taint", taint_map, [
    "sources", "sinks", "sanitizers",
  ])
  let sources = parse_rule_clause_array(
    expect_yaml_array(taint_map, path, "sources"),
    path,
    "taint.sources",
    false,
    true,
  )
  if sources.is_empty() {
    raise invalid_rule(path~, info="taint.sources must not be empty")
  }
  let sinks = parse_rule_clause_array(
    expect_yaml_array(taint_map, path, "sinks"),
    path,
    "taint.sinks",
    false,
    true,
  )
  if sinks.is_empty() {
    raise invalid_rule(path~, info="taint.sinks must not be empty")
  }
  let sanitizers = match taint_map.get("sanitizers") {
    None => []
    Some(@yaml.Yaml::Array(values)) =>
      parse_rule_clause_array(values, path, "taint.sanitizers", false, true)
    Some(_) => raise invalid_rule(path~, info="sanitizers must be an array")
  }
  { sources, sinks, sanitizers }
}

///|
fn parse_rule_clause_array(
  clauses_yaml : Array[@yaml.Yaml],
  path : String,
  context : String,
  allow_guard : Bool,
  reserve_taint_source : Bool,
) -> Array[@spec.RulePatternSpec] raise {
  let clauses : Array[@spec.RulePatternSpec] = []
  for index in 0..<clauses_yaml.length() {
    let clause_context = "\{context}[\{index}]"
    guard clauses_yaml[index] is @yaml.Yaml::Map(clause_map) else {
      raise invalid_rule(path~, info="\{clause_context} must be a mapping")
    }
    let allowed_keys = if allow_guard {
      ["shape", "metavars", "guard"]
    } else {
      ["shape", "metavars"]
    }
    ensure_allowed_keys(path, clause_context, clause_map, allowed_keys)
    let shape = expect_yaml_string(clause_map, path, "shape")
    let (subtree_metavars, identifier_metavars) = expect_metavars(
      clause_map, path, clause_context,
    )
    let metavars = pattern_declared_metavars(
      subtree_metavars, identifier_metavars,
    )
    ensure_metavars_safe(path, clause_context, metavars)
    if reserve_taint_source {
      ensure_taint_metavars_safe(path, clause_context, metavars)
    }
    let pattern_guard = expect_pattern_guard(
      clause_map, path, clause_context, allow_guard,
    )
    clauses.push({ shape, subtree_metavars, identifier_metavars, pattern_guard })
  }
  clauses
}

///|
fn ensure_allowed_keys(
  path : String,
  context : String,
  map : Map[String, @yaml.Yaml],
  allowed : Array[String],
) -> Unit raise {
  for entry in map.iter() {
    if !allowed.contains(entry.0) {
      raise invalid_rule(
        path~,
        info="\{context} contains unsupported key \{entry.0}",
      )
    }
  }
}

///|
fn expect_yaml_string(
  map : Map[String, @yaml.Yaml],
  path : String,
  key : String,
) -> String raise {
  match map.get(key) {
    Some(@yaml.Yaml::String(value)) => value
    Some(_) => raise invalid_rule(path~, info="\{key} must be a string")
    None => raise invalid_rule(path~, info="missing required key \{key}")
  }
}

///|
fn expect_yaml_array(
  map : Map[String, @yaml.Yaml],
  path : String,
  key : String,
) -> Array[@yaml.Yaml] raise {
  match map.get(key) {
    Some(@yaml.Yaml::Array(values)) => values
    Some(_) => raise invalid_rule(path~, info="\{key} must be an array")
    None => raise invalid_rule(path~, info="missing required key \{key}")
  }
}

///|
fn expect_description(
  map : Map[String, @yaml.Yaml],
  path : String,
) -> String raise {
  match map.get("description") {
    Some(@yaml.Yaml::String(value)) => value
    Some(_) => raise invalid_rule(path~, info="description must be a string")
    None => raise invalid_rule(path~, info="missing required key description")
  }
}

///|
fn expect_pattern_guard(
  map : Map[String, @yaml.Yaml],
  path : String,
  clause_context : String,
  allow_guard : Bool,
) -> String? raise {
  if !allow_guard && map.contains("guard") {
    raise invalid_rule(path~, info="\{clause_context}.guard is not supported")
  }
  match map.get("guard") {
    None => None
    Some(@yaml.Yaml::String(value)) => {
      let guard_source = value.trim().to_string()
      if guard_source == "" {
        raise invalid_rule(
          path~,
          info="\{clause_context}.guard must not be blank",
        )
      }
      validate_guard_source(path, clause_context, guard_source)
      Some(guard_source)
    }
    Some(_) =>
      raise invalid_rule(path~, info="\{clause_context}.guard must be a string")
  }
}

///|
fn expect_metavars(
  map : Map[String, @yaml.Yaml],
  path : String,
  clause_context : String,
) -> (Array[String], Array[String]) raise {
  match map.get("metavars") {
    Some(@yaml.Yaml::Map(meta_map)) => {
      ensure_allowed_keys(path, "\{clause_context}.metavars", meta_map, [
        "subtree", "identifier",
      ])
      let subtree = expect_metavar_bucket(
        meta_map, path, clause_context, "subtree",
      )
      let identifier = expect_metavar_bucket(
        meta_map, path, clause_context, "identifier",
      )
      ensure_metavar_buckets_disjoint(path, clause_context, subtree, identifier)
      (subtree, identifier)
    }
    Some(_) =>
      raise invalid_rule(
        path~,
        info="\{clause_context}.metavars must be a mapping",
      )
    None => ([], [])
  }
}

///|
fn expect_metavar_bucket(
  map : Map[String, @yaml.Yaml],
  path : String,
  clause_context : String,
  bucket : String,
) -> Array[String] raise {
  match map.get(bucket) {
    None => []
    Some(@yaml.Yaml::Array(values)) => {
      let metavars : Array[String] = []
      for index in 0..<values.length() {
        guard values[index] is @yaml.Yaml::String(meta_name) else {
          raise invalid_rule(
            path~,
            info="\{clause_context}.metavars.\{bucket}[\{index}] must be a string",
          )
        }
        if metavars.contains(meta_name) {
          raise invalid_rule(
            path~,
            info="\{clause_context}.metavars.\{bucket} contains duplicate metavar \{meta_name}",
          )
        }
        metavars.push(meta_name)
      }
      metavars
    }
    Some(_) =>
      raise invalid_rule(
        path~,
        info="\{clause_context}.metavars.\{bucket} must be an array",
      )
  }
}

///|
fn ensure_metavar_buckets_disjoint(
  path : String,
  clause_context : String,
  subtree : Array[String],
  identifier : Array[String],
) -> Unit raise {
  for meta_name in identifier {
    if subtree.contains(meta_name) {
      raise invalid_rule(
        path~,
        info="\{clause_context}.metavars contains duplicate metavar \{meta_name}",
      )
    }
  }
}

///|
fn pattern_declared_metavars(
  subtree_metavars : Array[String],
  identifier_metavars : Array[String],
) -> Array[String] {
  let metavars : Array[String] = []
  for meta_name in subtree_metavars {
    metavars.push(meta_name)
  }
  for meta_name in identifier_metavars {
    metavars.push(meta_name)
  }
  metavars
}

///|
fn ensure_metavars_safe(
  path : String,
  clause_context : String,
  metavars : Array[String],
) -> Unit raise {
  for meta_name in metavars {
    if @spec.is_builtin_ignore_metavar_name(meta_name) {
      raise invalid_rule(
        path~,
        info="\{clause_context} cannot declare metavar \{meta_name} because it is a built-in ignore placeholder",
      )
    } else if meta_name == "file" || meta_name == "hits" || meta_name == "loc" {
      raise invalid_rule(
        path~,
        info="\{clause_context} cannot declare metavar \{meta_name} because it conflicts with generated matcher locals",
      )
    } else if meta_name.has_prefix("__moongrep_") {
      raise invalid_rule(
        path~,
        info="\{clause_context} cannot declare metavar \{meta_name} because names starting with __moongrep_ are reserved for generated matcher locals",
      )
    }
  }
}

///|
fn ensure_taint_metavars_safe(
  path : String,
  clause_context : String,
  metavars : Array[String],
) -> Unit raise {
  if metavars.contains("__SOURCE__") {
    raise invalid_rule(
      path~,
      info="\{clause_context} cannot declare metavar __SOURCE__ because it is reserved for taint source targets",
    )
  }
}

///|
fn validate_guard_source(
  path : String,
  clause_context : String,
  guard_source : String,
) -> Unit raise {
  let guard_wrapper = "fn _guard_check() -> Unit {\n" +
    "  let _ = \{guard_source}\n" +
    "}\n"
  let (_program, reports) = @lexer.tokens_from_string(
      guard_wrapper,
      comment=true,
      name="pattern guard",
    ).tokens
    |> @handrolled_parser.parse()
  if reports is [err, ..] {
    raise invalid_rule(
      path~,
      info="\{clause_context}.guard is not a valid MoonBit expression: \{err.to_json().stringify(indent=2)}",
    )
  }
}

///|
fn rule_id_from_path(path : String, rules_root : String) -> String raise {
  let prefix = "\{rules_root}/"
  if !path.has_prefix(prefix) {
    raise invalid_rule(
      path~,
      info="rule path is outside rules root \{rules_root}",
    )
  }
  let relative = path[prefix.length():].to_string()
  if relative.has_suffix(".yaml") {
    relative[0:relative.length() - 5].to_string()
  } else if relative.has_suffix(".yml") {
    relative[0:relative.length() - 4].to_string()
  } else {
    raise invalid_rule(path~, info="unsupported rule file suffix")
  }
}
