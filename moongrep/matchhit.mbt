///|
pub(all) struct MatchHit {
  file : String
  rule_id : String
  package_name : String
  description : String
  pattern_index : Int
  loc : Json
  bindings : Json
} derive(Eq)

///|
pub impl Show for MatchHit with output(self, logger) {
  fn render_file_with_loc(file : String, loc : Json) -> String {
    match loc {
      {
        "start": {
          "line": Number(start_line, ..),
          "column": Number(start_column, ..),
          ..
        },
        "end": {
          "line": Number(end_line, ..),
          "column": Number(end_column, ..),
          ..
        },
        ..
      } => "\{file}:\{start_line}:\{start_column}-\{end_line}:\{end_column}"
      _ => file
    }
  }

  fn write_line(logger : &Logger, label : String, value : String) -> Unit {
    logger.write_string(label)
    logger.write_string(": ")
    logger.write_string(value)
  }

  fn write_block(logger : &Logger, label : String, value : String) -> Unit {
    logger.write_string(label)
    logger.write_string(":\n  ")
    logger.write_string(value.replace_all(old="\n", new="\n  "))
  }

  logger.write_string(render_file_with_loc(self.file, self.loc))
  logger.write_char('\n')
  write_line(logger, "rule", self.rule_id)
  logger.write_char('\n')
  write_block(
    logger,
    "description",
    self.description.trim_end(chars="\n").to_string(),
  )
}

///|
pub impl ToJson for MatchHit with to_json(self) {
  {
    "file": self.file,
    "rule_id": self.rule_id,
    "package": self.package_name,
    "description": self.description,
    "pattern_index": self.pattern_index,
    "loc": self.loc,
    "bindings": self.bindings,
  }
}
