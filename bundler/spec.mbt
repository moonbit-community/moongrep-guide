///|
priv struct RulePatternSpec {
  shape : String
  metavars : Array[String]
  pattern_guard : String?
}

///|
priv struct RuleSpec {
  rule_id : String
  package_name : String
  description : String
  patterns : Array[RulePatternSpec]
}
