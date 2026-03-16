# moongrep-guide

`moongrep-guide` is an Agent Skill that shows how to build structural MoonBit code search script.

## Install

+ Codex

```
mkdir -p ~/.codex/skills/moonbit
git clone https://github.com/moonbit-community/moongrep-guide ~/.codex/skills/moonbit/moongrep-guide
```

## Use

example:

```
> Use `moongrep-guide` to write a script that 
finds all functions whose bodies contain exactly one expression, 
where that expression has the form `self.$fieldname`, and prints 
the function name together with its corresponding location.
```
