///|
pub fn normalize_identifier_name(ast : Json) -> String? {
  match ast {
    { "kind": "Binder", "children": { "name": String(name), .. }, .. } =>
      Some(name)
    {
      "kind": "Expr::Ident",
      "children": {
        "id": {
          "kind": "Var",
          "children": {
            "name": {
              "kind": "LongIdent::Ident",
              "children": { "value": String(name), .. },
              ..
            },
            ..
          },
          ..
        },
        ..
      },
      ..
    } => Some(name)
    {
      "kind": "Pattern::Var",
      "children": {
        "value": {
          "kind": "Binder",
          "children": { "name": String(name), .. },
          ..
        },
        ..
      },
      ..
    } => Some(name)
    _ => None
  }
}

///|
pub fn is_unused_var(ast : Json, name : String) -> Bool {
  !contains_ident_with_shadow(ast, name, false)
}

///|
fn contains_ident_with_shadow(
  ast : Json,
  name : String,
  shadowed : Bool,
) -> Bool {
  match ast {
    {
      "kind": "Expr::Ident",
      "children": {
        "id": {
          "kind": "Var",
          "children": {
            "name": {
              "kind": "LongIdent::Ident",
              "children": { "value": String(found), .. },
              ..
            },
            ..
          },
          ..
        },
        ..
      },
      ..
    } => !shadowed && found == name
    {
      "kind": "InterpElem::Source",
      "children": { "source": String(source), .. },
      ..
    } => !shadowed && interp_source_contains_ident(source, name)
    {
      "kind": "Func::Lambda",
      "children": { "parameters": parameters, "body": body, .. },
      ..
    } => {
      let (parameters_contains_ident, body_shadowed) = contains_ident_in_lambda_parameters(
        parameters, name, shadowed,
      )
      parameters_contains_ident ||
      contains_ident_with_shadow(body, name, body_shadowed)
    }
    {
      "kind": "Expr::If",
      "children": { "cond": cond, "ifso": ifso, "ifnot": ifnot, .. },
      ..
    } => {
      if contains_ident_with_shadow(cond, name, shadowed) {
        return true
      }
      let ifso_shadowed = shadowed || binds_name(cond, name)
      contains_ident_with_shadow(ifso, name, ifso_shadowed) ||
      contains_ident_with_shadow(ifnot, name, shadowed)
    }
    {
      "kind": "Case",
      "children": { "pattern": pattern, "guard": guard_, "body": body, .. },
      ..
    } => {
      if contains_ident_with_shadow(pattern, name, shadowed) {
        return true
      }
      let body_shadowed = shadowed || binds_name(pattern, name)
      contains_ident_with_shadow(guard_, name, body_shadowed) ||
      contains_ident_with_shadow(body, name, body_shadowed)
    }
    {
      "kind": "LexCase",
      "children": { "pat": pattern, "guard": guard_, "body": body, .. },
      ..
    } => {
      if contains_ident_with_shadow(pattern, name, shadowed) {
        return true
      }
      let body_shadowed = shadowed || binds_name(pattern, name)
      contains_ident_with_shadow(guard_, name, body_shadowed) ||
      contains_ident_with_shadow(body, name, body_shadowed)
    }
    {
      "kind": "Expr::Let",
      "children": { "pattern": pattern, "expr": expr, "body": body, .. },
      ..
    } => {
      if contains_ident_with_shadow(pattern, name, shadowed) {
        return true
      }
      if contains_ident_with_shadow(expr, name, shadowed) {
        return true
      }
      let body_shadowed = shadowed || binds_name(pattern, name)
      contains_ident_with_shadow(body, name, body_shadowed)
    }
    {
      "kind": "Expr::LetMut",
      "children": { "binder": binder, "expr": expr, "body": body, .. },
      ..
    } => {
      if contains_ident_with_shadow(expr, name, shadowed) {
        return true
      }
      let body_shadowed = shadowed || binds_name(binder, name)
      contains_ident_with_shadow(body, name, body_shadowed)
    }
    {
      "kind": "Expr::LetFn",
      "children": { "name": binder, "func": func, "body": body, .. },
      ..
    } => {
      let body_shadowed = shadowed || binds_name(binder, name)
      contains_ident_with_shadow(func, name, body_shadowed) ||
      contains_ident_with_shadow(body, name, body_shadowed)
    }
    {
      "kind": "Expr::LetRec",
      "children": { "bindings": bindings, "body": body, .. },
      ..
    } => {
      let body_shadowed = shadowed || binds_name(bindings, name)
      contains_ident_with_shadow(bindings, name, body_shadowed) ||
      contains_ident_with_shadow(body, name, body_shadowed)
    }
    {
      "kind": "Expr::LetAnd",
      "children": { "bindings": bindings, "body": body, .. },
      ..
    } => {
      let body_shadowed = shadowed || binds_name(bindings, name)
      contains_ident_with_shadow(bindings, name, body_shadowed) ||
      contains_ident_with_shadow(body, name, body_shadowed)
    }
    {
      "kind": "Expr::For",
      "children": {
        "binders": binders,
        "condition": condition,
        "continue_block": continue_block,
        "body": body,
        "for_else": for_else,
        "where_clause": where_clause,
        ..
      },
      ..
    } => {
      if contains_ident_with_shadow(binders, name, shadowed) {
        return true
      }
      let loop_shadowed = shadowed ||
        binds_name(binders, name) ||
        binds_name(continue_block, name)
      contains_ident_with_shadow(condition, name, loop_shadowed) ||
      contains_ident_with_shadow(continue_block, name, loop_shadowed) ||
      contains_ident_with_shadow(body, name, loop_shadowed) ||
      contains_ident_with_shadow(for_else, name, loop_shadowed) ||
      contains_ident_with_shadow(where_clause, name, loop_shadowed)
    }
    {
      "kind": "Expr::ForEach",
      "children": {
        "binders": binders,
        "expr": expr,
        "body": body,
        "else_block": else_block,
        ..
      },
      ..
    } => {
      if contains_ident_with_shadow(expr, name, shadowed) {
        return true
      }
      let loop_shadowed = shadowed || binds_name(binders, name)
      contains_ident_with_shadow(body, name, loop_shadowed) ||
      contains_ident_with_shadow(else_block, name, shadowed)
    }
    { "children": children, .. } =>
      contains_ident_with_shadow(children, name, shadowed)
    Array(items) => {
      for item in items {
        if contains_ident_with_shadow(item, name, shadowed) {
          return true
        }
      }
      false
    }
    Object(entries) => {
      for _, value in entries.iter2() {
        if contains_ident_with_shadow(value, name, shadowed) {
          return true
        }
      }
      false
    }
    _ => false
  }
}

///|
fn contains_ident_in_lambda_parameters(
  parameters : Json,
  name : String,
  shadowed : Bool,
) -> (Bool, Bool) {
  match parameters {
    { "kind": "Func::Lambda::ParameterList", "children": Array(items), .. } =>
      contains_ident_in_parameter_items(items, name, shadowed)
    Array(items) => contains_ident_in_parameter_items(items, name, shadowed)
    _ =>
      (
        contains_ident_with_shadow(parameters, name, shadowed),
        shadowed || binds_name(parameters, name),
      )
  }
}

///|
fn contains_ident_in_parameter_items(
  items : Array[Json],
  name : String,
  shadowed : Bool,
) -> (Bool, Bool) {
  let mut current_shadowed = shadowed
  for item in items {
    if contains_ident_with_shadow(item, name, current_shadowed) {
      return (true, current_shadowed)
    }
    current_shadowed = current_shadowed || binds_name(item, name)
  }
  (false, current_shadowed)
}

///|
fn binds_name(ast : Json, name : String) -> Bool {
  match ast {
    { "kind": "Binder", "children": { "name": String(bound), .. }, .. } =>
      bound == name
    { "kind": String(kind), "children": children, .. } =>
      binds_name_in_children(kind, children, name)
    Array(items) => {
      for item in items {
        if binds_name(item, name) {
          return true
        }
      }
      false
    }
    Object(entries) => {
      for _, value in entries.iter2() {
        if binds_name(value, name) {
          return true
        }
      }
      false
    }
    _ => false
  }
}

///|
fn binds_name_in_children(
  kind : String,
  children : Json,
  name : String,
) -> Bool {
  match kind {
    "Expr::Is" =>
      match children {
        { "pat": pat, .. } => binds_name(pat, name)
        _ => false
      }
    "Parameter::Positional"
    | "Parameter::Labelled"
    | "Parameter::Optional"
    | "Parameter::QuestionOptional"
    | "LetRec::Binding"
    | "LetAnd::Binding"
    | "For::Binding"
    | "For::ContBinding" =>
      match children {
        { "binder": binder, .. } => binds_name(binder, name)
        _ => false
      }
    "Func::Lambda::ParameterList"
    | "Expr::ForEach::BinderList"
    | "Expr::For::BindingList"
    | "Expr::For::ContBindingList"
    | "Expr::LetRec::BindingList"
    | "Expr::LetAnd::BindingList"
    | "Pattern::Alias"
    | "Pattern::Any"
    | "Pattern::Array"
    | "Pattern::Constraint"
    | "Pattern::Constr"
    | "Pattern::Constr::ArgList"
    | "Pattern::Or"
    | "Pattern::Tuple"
    | "Pattern::Tuple::PatternList"
    | "Pattern::Var"
    | "Pattern::Record"
    | "Pattern::Record::FieldList"
    | "Pattern::Map"
    | "Pattern::Map::ElemList"
    | "Pattern::Range"
    | "Pattern::SpecialConstr"
    | "Pattern::SpecialConstr::ArgList"
    | "ConstrPatArg"
    | "FieldPat"
    | "MapPatElem"
    | "ArrayPattern::Pattern"
    | "ArrayPattern::StringSpread"
    | "ArrayPattern::BytesSpread"
    | "ArrayPattern::ConstSpread"
    | "ArrayPatterns::Closed"
    | "ArrayPatterns::Closed::PatternList"
    | "ArrayPatterns::Open"
    | "ArrayPatterns::Open::LPatternList"
    | "ArrayPatterns::Open::RPatternList" => binds_name(children, name)
    _ => false
  }
}

///|
fn interp_source_contains_ident(source : String, name : String) -> Bool {
  (source.trim().to_string() == name ||
  is_unused_var(dump_expr_json_repr(source), name)) catch {
    _ => false
  }
}
