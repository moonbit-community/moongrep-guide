///|
pub struct NameResolveEnv {
  // e.g
  // import {
  //   "randomuser/foo/bar",
  //   "randomuser/foo/baz" @boo
  // }
  //       ||
  //       ||
  //       \/
  // pkg_aliases: {
  //   "bar": "randomuser/foo/bar"
  //   "boo": "randomuser/foo/baz"
  // }
  pkg_aliases : Map[String, String]
  // e.g using @foo { bar, type Baz as Boo }
  //       ||
  //       ||
  //       \/
  // using_aliases: {
  //   "Boo": ("foo", Some("Baz"))
  //   "bar": ("foo", None)
  // }
  using_aliases : Map[String, (String, String?)]
}

///|
pub fn NameResolveEnv::resolve(
  self : NameResolveEnv,
  name : String,
  pkg? : String,
) -> (String, String)? {
  if pkg is Some(pkg) {
    Some((self.pkg_aliases[pkg], name))
  } else if self.using_aliases.get(name) is Some((pkg, alias_)) {
    let name = alias_.unwrap_or(name)
    Some((self.pkg_aliases[pkg], name))
  } else {
    None
  }
}
