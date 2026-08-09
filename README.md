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
P101FACT<TAB>7<TAB>kind<TAB>path<TAB>module<TAB>is_header<TAB>line...
```

The current and only accepted version is `7`, defined by `P101_C_FACT_VERSION`
in `include/p101_c_facts/facts.h`. Extra fields depend on `kind`:

| Kind | Extra fields |
| --- | --- |
| `FILE` | none |
| `INCLUDE` | `target`, `is_local` |
| `FUNCTION` | `name`, `is_static`, `is_header_declaration`, `usr`, `start`, `end` |
| `CALL` | `name`, `needs_env`, `needs_error`, `is_indirect`, `caller`, `usr`, `caller_usr`, `start`, `end` |
| `TYPE` | `name`, `usr` |
| `ENUM` | `name`, `usr` |
| `ENUMERATOR` | `name`, `enum_type`, `usr`, `enum_usr` |
| `MACRO` | `name`, `is_definition`, `caller_usr`, `start`, `end` |
| `NOTE` | `name`, `caller`, `column`, `caller_usr`, `start`, `end` |

Variable fields escape backslash, tab, newline, and carriage return as `\\`,
`\t`, `\n`, and `\r`.

Known `NOTE` values include `ENV_CONTRACT`, `ERROR_CONTRACT`, `ENV_USE`,
`ERROR_USE`, `TYPE_SEMANTIC_ROLE:<role>`, `ERROR_CHECK`, `ERROR_OPTIONAL`, `ERROR_DISCARD`,
`ERROR_PROPAGATED`, `ERROR_UNCHECKED_CHAIN`, `FUNCTION_RETURN`,
`FUNCTION_EARLY_RETURN`, `SEMANTIC_ROLE:<role>`,
`FUNCTION_REFERENCE:<function-usr>`, and
`CALLEE_SEMANTIC_ROLE:<role>`. The latter is emitted at a call site from the
AST-resolved declaration's annotation, so consumers do not have to infer a
callee's purpose from its spelling. Consumers
should ignore note values they do not understand.

`FUNCTION_REFERENCE` records a resolved function declaration used as a value,
including callback and test-runner registration. This lets policy distinguish
an unwired function from one registered through a macro without matching
variable or function names.

Indirect-call records use the declaration identity of the function-pointer
type when one exists. This lets policy describe a callback by its actual type,
not by the local variable or structure-member name used at one call site.
`CALL_RESULT_DISCARDED` identifies a call expression whose value is an
expression statement or is explicitly converted to `void`.

The two `CALL` flags are derived from the resolved callee declaration in
Clang's AST. Declaration USRs, canonical record types, semantic-role
attributes, enclosing-function identities, and source extents are the policy
evidence. Display names remain in the format for people, but consumers must
not use them as a substitute for declaration identity. Macro spelling is
retained because a macro has no runtime function identity; its AST kind,
expansion extent, and enclosing function distinguish it from text search.

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
