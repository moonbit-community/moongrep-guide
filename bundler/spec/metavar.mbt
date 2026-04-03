///|
pub fn is_builtin_ignore_metavar_name(name : String) -> Bool {
  if name.length() < 2 {
    false
  } else {
    for ch in name.iter() {
      if ch != '_' {
        return false
      }
    }
    true
  }
}
