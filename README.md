# lib_c_facts

`lib_c_facts` owns the shared `P101FACT` record format used by p101 tools that
need C project facts without each tool inventing its own C parser.

The producer today is `p101-wrapper-audit --emit-module-facts`, which uses
Clang's AST and emits tab-separated records. Consumers, such as
`p101-module-map`, parse those records through this library.

## Record format

```text
P101FACT<TAB>1<TAB>kind<TAB>path<TAB>module<TAB>is_header<TAB>line...
```

The current version is `1`. Extra fields depend on `kind`:

| Kind | Extra fields |
| --- | --- |
| `FILE` | none |
| `INCLUDE` | `target`, `is_local` |
| `FUNCTION` | `name`, `is_static`, `is_header_declaration` |
| `CALL` | `name` |
| `TYPE` | `name` |
| `MACRO` | `name` |
| `NOTE` | `name` |

Variable fields escape backslash, tab, newline, and carriage return as `\\`,
`\t`, `\n`, and `\r`.

Known `NOTE` values include `ENV_CONTRACT`, `ERROR_CONTRACT`, `ENV_USE`,
`ERROR_USE`, `TRACE_USE`, and `ERROR_CHECK`. Consumers should ignore note values
they do not understand.
