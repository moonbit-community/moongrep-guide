# `taint` 包示例

这个包现在围绕三组概念工作：

- `StoragePath`
  表示当前函数里一个可寻址的位置，比如 `req.profile.email`。
- `ValueSite`
  表示诊断里的“值来自哪里”或“sink 消费了哪个值”。
- declarative `TaintSpec`
  用 `sources` 和 `call_models` 描述大多数规则，再用
  `custom_transfer_call` 处理少数复杂场景。

## 一个最小规则

下面这条规则表达了四件事：

- `req.profile.email` 是 entry source
- `input()` 的返回值也是 source
- `sanitize(x)` 会清理参数 `x`
- `sink(x)` 如果读到污点就报问题

```moonbit
let spec : TaintSpec = {
  rule_id: "demo",
  sources: [
    SourceModel::EntryPath(
      {
        root: "req",
        segments: [PathSegment::Field("profile"), PathSegment::Field("email")],
      },
      "req.email",
      Some("request email"),
    ),
    SourceModel::CallReturn(
      CallMatcher::CalleeName("input"),
      "input",
      Some("input()"),
      [],
    ),
  ],
  call_models: [
    {
      matcher: CallMatcher::CalleeName("sanitize"),
      effects: [CallEffect::KillArg(0)],
    },
    {
      matcher: CallMatcher::CalleeName("id"),
      effects: [CallEffect::PropagateArgToReturn(0)],
    },
    {
      matcher: CallMatcher::CalleeName("sink"),
      effects: [CallEffect::ReportSinkArg("sink", 0)],
    },
  ],
  unknown_call_policy: UnknownCallPolicy::NoEffect,
  max_fixpoint_iterations: 6,
  custom_transfer_call: (_) => None,
}
```

## 读这个规则时该怎么理解

### 1. `sources`

`SourceModel::EntryPath` 把函数入口参数里的某条 `StoragePath` 标成 source。

`SourceModel::CallReturn` 把“某个调用返回污点值”提升成一等概念，所以
`input()` 不再需要伪造路径。

### 2. `call_models`

`CallEffect` 是最常用的调用语义 DSL：

- `ReturnFreshSource`
- `PropagateArgToReturn`
- `PropagateReceiverToReturn`
- `PropagateArgSubpathToReturn`
- `KillArg`
- `KillReceiver`
- `ReportSinkArg`
- `ReportSinkReceiver`

大多数 source / sink / sanitizer / passthrough 都可以直接由这些 effect
组合出来。

### 3. `ValueSite`

诊断不再强迫所有值都伪装成路径：

- `sink(current)` 的 `sink_site` 通常是 `ValueSite::Path(...)`
- `sink(input())` 的 `sink_site` 可以直接是
  `ValueSite::CallResult(Some("input"), loc)`

同样，`TaintOrigin.site` 也可以准确表达 provenance：

- 参数 source: `ValueSite::Path(...)`
- 调用返回值 source: `ValueSite::CallResult(...)`

## 运行后会得到什么

分析结果还是 `AnalysisResult`，其中包含 `findings : Array[SinkFinding]`。

每条 `SinkFinding` 里最关键的是：

- `rule_id`
- `sink_id`
- `sink_loc`
- `sink_site`
- `origins`

这使得两个以前很别扭的场景现在都能自然表达：

1. `let x = input(); sink(x)`
   `origins[0].site` 是 `CallResult("input", ...)`
2. `sink(input())`
   `sink_site` 也是 `CallResult("input", ...)`

## 什么时候还需要 `custom_transfer_call`

如果规则超出 DSL 能力，比如要看更复杂的 AST 细节，或者要同时决定：

- 返回值 taint
- kill 哪些路径
- 生成哪些自定义 findings

就可以使用 `custom_transfer_call`。

但包的默认方向已经变成：

- 高频场景优先 declarative
- 复杂场景再用 escape hatch
