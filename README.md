# desercheck

Static detector for dangerous deserialization payloads. Pure Python
standard library -- no third-party packages, and **no execution**: the
samples are never run, imported, unpickled, or evaluated. Detection is
entirely byte- and text-level static analysis.

## What it recognizes

| kind     | signature                                                        | dangerous when |
|----------|------------------------------------------------------------------|----------------|
| `pickle` | well-formed opcode stream ending in STOP                         | a whitelisted dangerous opcode appears |
| `java`   | magic bytes `AC ED 00 05` + TC_* type markers                    | TC_OBJECT / TC_CLASSDESC / TC_CLASS / TC_PROXYCLASSDESC / TC_ENUM present |
| `yaml`   | dangerous custom tags in the text                                | always (any matched tag) |
| `json`   | parses as JSON                                                   | some object has a `__reduce__` key |

## Pickle opcode whitelist

The scanner walks the stream with `pickletools.genops` (a pure decoder --
it never imports modules or calls callables, unlike `pickle.loads`).
Exactly these opcodes are dangerous, because each one makes the
unpickler *do* something instead of just describing data:

- `GLOBAL`, `STACK_GLOBAL` -- import and push a module attribute by name
  (this is how `os.system` & friends enter the stream)
- `REDUCE` -- calls a callable with stack-supplied arguments
- `INST`, `OBJ` -- instantiate a class resolved from the stream
- `BUILD` -- applies state (`__setstate__` / dict update) to an object
- `NEWOBJ`, `NEWOBJ_EX` -- call `cls.__new__` with attacker-controlled args
- `EXT1`, `EXT2`, `EXT4` -- resolve objects from the extension registry

Everything else (literal pushers like `INT`/`STRING`/`BINUNICODE`,
container builders like `EMPTY_DICT`/`LIST`/`SETITEMS`, memo and stack
plumbing, `STOP`) is inert data description and counts as safe. The
judgement is purely opcode-based -- no string matching on payload
content -- so a `GLOBAL` payload rewritten as `STACK_GLOBAL` is still
caught.

## Text forms

Binary payloads are often smuggled as text. After UTF-8 decoding the
detector tries, in order:

1. **base64** -- strict-decode (`validate=True`); on success the decoded
   bytes go through the same Java/pickle scanners, so the verdict is
   identical to the binary form (`encoding: "base64"` in the report).
2. **hex** -- `bytes.fromhex`; same re-scan (`encoding: "hex"`).
3. **YAML tags** -- regex for `!!python/object/apply`,
   `!!python/object/new`, `!!python/object`, `!!python/name:`,
   `!!python/module:`, `!ruby/object`, `!perl/...`, `!php/object`.
4. **JSON** -- `json.loads` (inert: builds only plain containers), then
   a recursive walk for any object carrying a `__reduce__` key.

## Report conventions

Each sample entry in the JSON report has:

- `kind` -- `pickle` | `java` | `yaml` | `json` | `unknown`
- `dangerous` -- boolean verdict
- `evidence` -- list of strings; only names/markers, never payload code:
  - pickle: `opcode:<NAME>@byte:<N> (<reason>)`
  - java: `magic:0xaced0005`, `marker:TC_OBJECT`, ...
  - yaml: `tag:!!python/object/apply`, ...
  - json: `key:__reduce__`
- `first_danger_offset` -- 0-based byte offset of the first dangerous
  opcode in the (decoded) stream; `null` for safe samples and non-opcode
  kinds (yaml reports the tag's text offset, java reports 0)
- `encoding` -- `binary` | `base64` | `hex` | `text`

## Usage

```
python -m desercheck.cli --samples demo/samples --out out/report.json
```

writes the JSON report and prints a one-line summary to stdout, e.g.

```
samples=10 dangerous=7 safe=3 dangerous_kinds=java:1,json:1,pickle:4,yaml:1
```

Regenerate the demo samples with `python demo/make_samples.py`.

## Tests

```
cd tests && python -m unittest test_desercheck -v
```

All fixtures are generated programmatically in temporary directories at
test time; no verdict is hard-coded to a specific sample directory.
