# lib_c_facts

`lib_c_facts` owns both native libclang acquisition and the shared `P101FACT`
record format used by p101 tools that need C project facts without each tool
inventing its own C parser.

`p101-wrapper-audit` and `p101-c-facts` call the library's acquisition API and
emit tab-separated records. Consumers, such as `p101-module-map`, parse those
records through this library. `p101-mutation-check` consumes the same native
analysis records directly so source extents do not make a text-format
round-trip.

## Record format

```text
P101FACT<TAB>4<TAB>kind<TAB>path<TAB>module<TAB>is_header<TAB>line...
```

The current version is `4`. Extra fields depend on `kind`:

| Kind | Extra fields |
| --- | --- |
| `FILE` | none |
| `INCLUDE` | `target`, `is_local` |
| `FUNCTION` | `name`, `is_static`, `is_header_declaration` |
| `CALL` | `name`, `needs_env`, `needs_error`, `caller` |
| `TYPE` | `name` |
| `ENUM` | `name` |
| `ENUMERATOR` | `name`, `enum_type` |
| `MACRO` | `name` |
| `NOTE` | `name`, `caller`, `column` |

Variable fields escape backslash, tab, newline, and carriage return as `\\`,
`\t`, `\n`, and `\r`.

Known `NOTE` values include `ENV_CONTRACT`, `ERROR_CONTRACT`, `ENV_USE`,
`ERROR_USE`, `TRACE_USE`, `ERROR_CHECK`, `ERROR_OPTIONAL`, `ERROR_DISCARD`,
`ERROR_PROPAGATED`, `ERROR_UNCHECKED_CHAIN`, and `FUNCTION_RETURN`. Consumers
should ignore note values they do not understand.

The two `CALL` flags are derived from the resolved callee declaration in
Clang's AST. `CALL` and `NOTE` records preserve the enclosing function across
replay. Together they let policy tools reason from the actual wrapper
signature and enforce caller-sensitive rules without maintaining private name
lists.

## Ownership and compatibility

`lib_c_facts` owns the Clang parsing pass and this versioned parser contract.
Error handling, wrapper-boundary rules, module-design thresholds, mutation
policy, and other judgments remain in their individual tools.

Older versions are intentionally rejected. A consumer must not silently
interpret a snapshot with different call semantics.

The acquisition API reports only translation units admitted by the requested
paths and compile database. Its error-flow notes use resolved AST calls and
source locations, but deliberately conservative statement-path reasoning; they
are evidence for a teaching policy, not a compiler control-flow proof.

Compile databases may originate from GCC or Clang, but parsing is performed by
libclang. The acquisition boundary therefore admits language mode, definitions,
include paths, target/sysroot settings, and other syntax-affecting arguments,
while discarding compiler-specific diagnostics, optimization, instrumentation,
and code-generation flags. This preserves the source configuration needed for
the AST without asking libclang to understand another compiler's private flag
surface.
