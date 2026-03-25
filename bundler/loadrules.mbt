///|
fn load_rules(rules_root : String) -> Array[RuleSpec] raise {
  let files = collect_rule_files(rules_root)
  if files.is_empty() {
    raise InvalidRule(path=rules_root, info="no YAML rule files found")
  }
  let rules : Array[RuleSpec] = []
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
) -> RuleSpec raise {
  let docs = @yaml.Yaml::load_from_string(source)
  if docs.length() != 1 {
    raise InvalidRule(
      path~,
      info="rule file must contain exactly one YAML document",
    )
  }
  guard docs[0] is @yaml.Yaml::Map(doc) else {
    raise InvalidRule(path~, info="top-level YAML document must be a mapping")
  }
  ensure_allowed_keys(path, "top-level rule", doc, [
    "package", "description", "describle", "patterns",
  ])
  let package_name = expect_yaml_string(doc, path, "package")
  let description = expect_description(doc, path)
  let patterns_yaml = expect_yaml_array(doc, path, "patterns")
  if patterns_yaml.is_empty() {
    raise InvalidRule(path~, info="patterns must not be empty")
  }
  let patterns : Array[RulePatternSpec] = []
  for index in 0..<patterns_yaml.length() {
    let pattern_yaml = patterns_yaml[index]
    guard pattern_yaml is @yaml.Yaml::Map(pattern_map) else {
      raise InvalidRule(path~, info="patterns[\{index}] must be a mapping")
    }
    ensure_allowed_keys(path, "pattern[\{index}]", pattern_map, [
      "shape", "metavars", "guard",
    ])
    let shape = expect_yaml_string(pattern_map, path, "shape")
    let metavars_yaml = expect_yaml_array(pattern_map, path, "metavars")
    let metavars : Array[String] = []
    for meta_index in 0..<metavars_yaml.length() {
      guard metavars_yaml[meta_index] is @yaml.Yaml::String(meta_name) else {
        raise InvalidRule(
          path~,
          info="patterns[\{index}].metavars[\{meta_index}] must be a string",
        )
      }
      if metavars.contains(meta_name) {
        raise InvalidRule(
          path~,
          info="patterns[\{index}] contains duplicate metavar \{meta_name}",
        )
      }
      metavars.push(meta_name)
    }
    let pattern_guard = expect_pattern_guard(pattern_map, path, index, metavars)
    patterns.push({ shape, metavars, pattern_guard })
  }
  {
    rule_id: rule_id_from_path(path, rules_root),
    package_name,
    description,
    patterns,
  }
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
      raise InvalidRule(
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
    Some(_) => raise InvalidRule(path~, info="\{key} must be a string")
    None => raise InvalidRule(path~, info="missing required key \{key}")
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
    Some(_) => raise InvalidRule(path~, info="\{key} must be an array")
    None => raise InvalidRule(path~, info="missing required key \{key}")
  }
}

///|
fn expect_description(
  map : Map[String, @yaml.Yaml],
  path : String,
) -> String raise {
  match map.get("description") {
    Some(@yaml.Yaml::String(value)) => value
    Some(_) => raise InvalidRule(path~, info="description must be a string")
    None =>
      match map.get("describle") {
        Some(@yaml.Yaml::String(value)) => value
        Some(_) => raise InvalidRule(path~, info="describle must be a string")
        None =>
          raise InvalidRule(path~, info="missing required key description")
      }
  }
}

///|
fn expect_pattern_guard(
  map : Map[String, @yaml.Yaml],
  path : String,
  pattern_index : Int,
  metavars : Array[String],
) -> String? raise {
  match map.get("guard") {
    None => None
    Some(@yaml.Yaml::String(value)) => {
      let guard_source = value.trim().to_string()
      if guard_source == "" {
        raise InvalidRule(
          path~,
          info="patterns[\{pattern_index}].guard must not be blank",
        )
      }
      ensure_guard_metavars_safe(path, pattern_index, metavars)
      validate_guard_source(path, pattern_index, guard_source)
      Some(guard_source)
    }
    Some(_) =>
      raise InvalidRule(
        path~,
        info="patterns[\{pattern_index}].guard must be a string",
      )
  }
}

///|
fn ensure_guard_metavars_safe(
  path : String,
  pattern_index : Int,
  metavars : Array[String],
) -> Unit raise {
  for meta_name in metavars {
    if meta_name == "file" || meta_name == "hits" || meta_name == "loc" {
      raise InvalidRule(
        path~,
        info="patterns[\{pattern_index}].guard cannot expose metavar \{meta_name} because it conflicts with generated matcher locals",
      )
    }
  }
}

///|
fn validate_guard_source(
  path : String,
  pattern_index : Int,
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
    raise InvalidRule(
      path~,
      info="patterns[\{pattern_index}].guard is not a valid MoonBit expression: \{err.to_json().stringify(indent=2)}",
    )
  }
}

///|
fn rule_id_from_path(path : String, rules_root : String) -> String raise {
  let prefix = "\{rules_root}/"
  if !path.has_prefix(prefix) {
    raise InvalidRule(
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
    raise InvalidRule(path~, info="unsupported rule file suffix")
  }
}
