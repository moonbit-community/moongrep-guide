///|
pub suberror RuleBundleError {
  InvalidRule(path~ : String, info~ : String)
} derive(Show)

///|
pub fn invalid_rule(path~ : String, info~ : String) -> RuleBundleError {
  InvalidRule(path~, info~)
}

///|
pub fn RuleBundleError::unwrap_invalid_rule(
  self : RuleBundleError,
) -> (String, String) {
  match self {
    InvalidRule(path~, info~) => (path, info)
  }
}

///|
pub(all) struct RulePatternSpec {
  shape : String
  subtree_metavars : Array[String]
  identifier_metavars : Array[String]
  pattern_guard : String?
}

///|
pub fn RulePatternSpec::declared_metavars(
  self : RulePatternSpec,
) -> Array[String] {
  let metavars : Array[String] = []
  for meta_name in self.subtree_metavars {
    metavars.push(meta_name)
  }
  for meta_name in self.identifier_metavars {
    metavars.push(meta_name)
  }
  metavars
}

///|
pub(all) struct RuleSpec {
  rule_id : String
  package_name : String
  description : String
  patterns : Array[RulePatternSpec]
}
