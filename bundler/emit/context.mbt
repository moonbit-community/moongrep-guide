///|
priv struct BindingRecord {
  meta_name : String
  bind_names : Array[String]
}

///|
priv struct PatternEmitContext {
  declared_metavars : Array[String]
  bindings : Array[BindingRecord]
}
