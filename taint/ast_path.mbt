// AST extraction helpers shared by the taint engine.
//
// This file turns parser JSON into the smaller set of facts the engine needs:
// - source locations
// - absolute access paths for reads/writes
// - binder names for scope restoration
// - normalized top-level function metadata

///|
/// Minimal parameter shape used when seeding entry-point taint.
priv struct ParameterInfo {
  name : String
}

///|
/// Common representation for both top-level functions and top-level impl
/// methods so the engine can treat them uniformly.
priv struct FunctionLikeInfo {
  function_name : String
  function_loc : Json
  parameters : Array[ParameterInfo]
  body : Json
}

///|
fn json_loc(ast : Json) -> Json {
  match ast {
    { "loc": loc, .. } => loc
    _ => null
  }
}

///|
fn json_child(ast : Json, key : String) -> Json? {
  match ast {
    { "children": Object(children), .. } => children.get(key)
    _ => None
  }
}

///|
fn json_children(ast : Json) -> Json? {
  match ast {
    { "children": children, .. } => Some(children)
    _ => None
  }
}

///|
fn json_int(json : Json) -> Int? {
  match json {
    Number(value, ..) => Some(value.to_int())
    _ => None
  }
}

///|
fn extract_long_ident_name(ast : Json) -> String? {
  match ast {
    {
      "kind": "LongIdent::Ident",
      "children": { "value": String(value), .. },
      ..
    } => Some(value)
    {
      "kind": "LongIdent::Dot",
      "children": { "pkg": String(pkg), "id": String(id), .. },
      ..
    } => Some("\{pkg}.\{id}")
    _ => None
  }
}

///|
fn extract_var_name(ast : Json) -> String? {
  match ast {
    { "kind": "Var", "children": { "name": name, .. }, .. } =>
      extract_long_ident_name(name)
    _ => None
  }
}

///|
fn extract_ident_name(ast : Json) -> String? {
  match ast {
    { "kind": "Expr::Ident", "children": { "id": id, .. }, .. } =>
      extract_var_name(id)
    _ => None
  }
}

///|
fn extract_label_name(ast : Json) -> String? {
  match ast {
    { "kind": "Label", "children": { "name": String(name), .. }, .. } =>
      Some(name)
    _ => None
  }
}

///|
fn accessor_segment(accessor : Json) -> PathSegment? {
  match accessor {
    { "kind": "Accessor::Label", "children": { "value": value, .. }, .. } =>
      match extract_label_name(value) {
        Some(name) => Some(PathSegment::Field(name))
        None => None
      }
    { "kind": "Accessor::Index", "children": { "tuple_index": value, .. }, .. } =>
      match json_int(value) {
        Some(index) => Some(PathSegment::TupleIndex(index))
        None => None
      }
    _ => None
  }
}

///|
fn index_segment(index_ast : Json) -> PathSegment {
  match index_ast {
    {
      "kind": "Expr::Constant",
      "children": {
        "constant": {
          "kind": "Constant::Int",
          "children": { "value": String(value), .. },
          ..
        },
        ..
      },
      ..
    } => PathSegment::ConstIndex(value)
    {
      "kind": "Expr::Constant",
      "children": {
        "constant": {
          "kind": "Constant::String",
          "children": { "value": String(value), .. },
          ..
        },
        ..
      },
      ..
    } => PathSegment::ConstIndex(value)
    _ => PathSegment::AnyIndex
  }
}

///|
/// Extract a precise storage path when an expression is path-like.
///
/// Examples that succeed:
/// - `x`
/// - `x.field`
/// - `tuple.0`
/// - `arr[i]`
///
/// Expressions with effects or computed base values return `None`, which tells
/// the engine to keep only value taint and not path-specific state updates.
fn extract_storage_path(ast : Json) -> StoragePath? {
  match ast {
    { "kind": "Expr::Ident", "children": { "id": id, .. }, .. } =>
      match extract_var_name(id) {
        Some(name) => Some(storage_path(name))
        None => None
      }
    {
      "kind": "Expr::Field",
      "children": { "record": record, "accessor": accessor, .. },
      ..
    } =>
      match (extract_storage_path(record), accessor_segment(accessor)) {
        (Some(base), Some(segment)) =>
          Some({
            root: base.root,
            segments: append_segments(base.segments, [segment]),
          })
        _ => None
      }
    {
      "kind": "Expr::ArrayGet",
      "children": { "array": array, "index": index, .. },
      ..
    } =>
      match extract_storage_path(array) {
        Some(base) =>
          Some({
            root: base.root,
            segments: append_segments(base.segments, [index_segment(index)]),
          })
        None => None
      }
    _ => None
  }
}

///|
/// Collect all names introduced by a pattern.
///
/// The engine uses this to know which roots are shadowed inside `match`,
/// `catch`, and destructuring bindings so it can restore outer scope later.
fn collect_pattern_binder_names(pattern : Json) -> Array[String] {
  let names : Array[String] = []
  collect_pattern_binder_names_into(pattern, names)
  names
}

///|
fn collect_pattern_binder_names_into(
  pattern : Json,
  names : Array[String],
) -> Unit {
  match pattern {
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
    } => if !names.contains(name) { names.push(name) }
    { "children": Array(items), .. } =>
      for item in items {
        collect_pattern_binder_names_into(item, names)
      }
    { "children": Object(children), .. } =>
      for _, value in children.iter2() {
        collect_pattern_binder_names_into(value, names)
      }
    Array(items) =>
      for item in items {
        collect_pattern_binder_names_into(item, names)
      }
    Object(children) =>
      for _, value in children.iter2() {
        collect_pattern_binder_names_into(value, names)
      }
    _ => ()
  }
}

///|
/// Collect binders introduced by a group of nested binding declarations.
///
/// This is used when crossing function boundaries (`let fn`, `let rec`,
/// `let and`) so the outer analysis can kill the newly-bound roots.
fn collect_binding_binder_names(ast : Json) -> Array[String] {
  let names : Array[String] = []
  collect_binding_binder_names_into(ast, names)
  names
}

///|
fn collect_binding_binder_names_into(ast : Json, names : Array[String]) -> Unit {
  match ast {
    { "kind": "Binder", "children": { "name": String(name), .. }, .. } =>
      if !names.contains(name) {
        names.push(name)
      }
    { "children": Array(items), .. } =>
      for item in items {
        collect_binding_binder_names_into(item, names)
      }
    { "children": Object(children), .. } =>
      for _, value in children.iter2() {
        collect_binding_binder_names_into(value, names)
      }
    Array(items) =>
      for item in items {
        collect_binding_binder_names_into(item, names)
      }
    Object(children) =>
      for _, value in children.iter2() {
        collect_binding_binder_names_into(value, names)
      }
    _ => ()
  }
}

///|
/// Extract one positional parameter's binder information.
fn extract_parameter_info(ast : Json) -> ParameterInfo? {
  match ast {
    {
      "kind": "Parameter::Positional",
      "children": {
        "binder": {
          "kind": "Binder",
          "children": { "name": String(name), .. },
          ..
        },
        ..
      },
      ..
    } => Some({ name, })
    _ => None
  }
}

///|
fn render_type_name(ast : Json) -> String? {
  match ast {
    { "kind": "TypeName", "children": { "name": name, .. }, .. } =>
      extract_long_ident_name(name)
    _ => None
  }
}

///|
/// Normalize a supported top-level function-like node to a common shape.
///
/// `TopFuncDef` keeps its declared name. `TopImpl` is rendered as
/// `Owner::method` so reports remain stable and readable for methods.
fn extract_function_like_info(ast : Json) -> FunctionLikeInfo? {
  match ast {
    {
      "kind": "Impl::TopFuncDef",
      "loc": function_loc,
      "children": {
        "fun_decl": {
          "kind": "FunDecl",
          "children": {
            "name": {
              "kind": "Binder",
              "children": { "name": String(function_name), .. },
              ..
            },
            "decl_params": {
              "kind": "FunDecl::ParameterList",
              "children": Array(params),
              ..
            },
            ..
          },
          ..
        },
        "decl_body": {
          "kind": "DeclBody::DeclBody",
          "children": { "expr": body, .. },
          ..
        },
        ..
      },
      ..
    } => {
      let parameters : Array[ParameterInfo] = []
      for param in params {
        match extract_parameter_info(param) {
          Some(info) => parameters.push(info)
          None => ()
        }
      }
      Some({ function_name, function_loc, parameters, body })
    }
    {
      "kind": "Impl::TopImpl",
      "loc": function_loc,
      "children": {
        "trait": trait_name,
        "self_ty": self_ty,
        "method_name": {
          "kind": "Binder",
          "children": { "name": String(method_name), .. },
          ..
        },
        "params": {
          "kind": "Impl::TopImpl::ParamList",
          "children": Array(params),
          ..
        },
        "body": {
          "kind": "DeclBody::DeclBody",
          "children": { "expr": body, .. },
          ..
        },
        ..
      },
      ..
    } => {
      let parameters : Array[ParameterInfo] = []
      for param in params {
        match extract_parameter_info(param) {
          Some(info) => parameters.push(info)
          None => ()
        }
      }
      let owner = match self_ty {
        Null =>
          match render_type_name(trait_name) {
            Some(name) => name
            None => "impl"
          }
        _ =>
          match render_type_name(self_ty) {
            Some(name) => name
            None => "impl"
          }
      }
      Some({
        function_name: "\{owner}::\{method_name}",
        function_loc,
        parameters,
        body,
      })
    }
    _ => None
  }
}
