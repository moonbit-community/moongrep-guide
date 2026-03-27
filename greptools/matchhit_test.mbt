///|
test "show match hit prints file with decoded location" {
  let hit = MatchHit::{
    file: "sample.mbt",
    rule_id: "demo/rule",
    package_name: "moonbit-community/demo",
    description: "demo description\n",
    pattern_index: 0,
    loc: {
      "file": "sample.mbt",
      "start": { "line": 2, "column": 10 },
      "end": { "line": 2, "column": 24 },
    },
  }
  let expected =
    #|sample.mbt:2:10-2:24
    #|rule: demo/rule
    #|description:
    #|  demo description
  inspect(Show::to_string(hit), content=expected)
}
