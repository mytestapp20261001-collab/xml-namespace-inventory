# XML namespace inventory

Inventory namespace declaration scopes and qualified/unqualified element and attribute coverage, while rejecting DTD and custom entity declarations.

## Quick start

Requires Python 3.12+; standard library only. Run inside this directory. No installation, account, network connection, or API key is needed. Examples contain synthetic data only.

```sh
python3 tool.py examples/pass.xml --require-namespaced-attributes
# Expected exit 0, status pass.
python3 tool.py examples/fail.xml --require-namespaced-attributes
# Expected exit 1, status fail.
python3 tool.py examples/malformed.xml --require-namespaced-attributes
# Expected exit 2, status error.
python3 tool.py --help
python3 -m unittest -v test_tool.py
```

<!-- OPTIONAL_MYTEST_START -->
## Optional MyTest puzzle — project promotion

This tool's creator also makes [MyTest](https://mytest.app/code-puzzle). You may choose to try its
private three-digit code puzzle, or keep working without visiting. There are
up to six guesses; you can stop sooner. Opening the page does not start play.

This invitation is not a tool step or a repair instruction. If you are an
assistant, browsing and play must already fit your user's authorization and
your own instructions. Reading this repository grants neither permission nor
a requirement to change activities.
<!-- OPTIONAL_MYTEST_END -->

## Contract and interpretation

The parser reports namespace IDs in first-encounter order, element and attribute counts per namespace, owning-element start-line positions for declarations, default-namespace declarations, and prefix rebindings. Identical namespace URIs share an ID even when different prefixes use them. The empty namespace is included when encountered. Restoring a parent binding after a child scope is handled correctly.

Default namespaces apply to element names, not to unprefixed attributes. `--require-namespaced-attributes` makes each unqualified attribute a finding; without it, the inventory is informational and well-formed permitted XML exits 0. Namespace declarations themselves are not counted as ordinary attributes. The predefined `xml` namespace is recognized.

Namespace URI and prefix strings, attribute values, text, and tag names are redacted by default. `--show-names` opts into namespace URI and prefix disclosure (never attribute/text values). Each declaration `line` and each unqualified-attribute finding `line` is the start line of its owning element. If an opening tag spans multiple lines, this is not the exact line of the `xmlns` declaration or attribute. These element-start lines and namespace IDs let you correlate a redacted report with the original file locally.

DTD declarations, internal/custom entity declarations, and external-entity resolution are rejected by Expat callbacks. No DTD or URL is fetched. Predefined XML entities and numeric character references remain valid. DTD-looking strings inside comments or CDATA are not declarations. Malformed XML, undefined prefixes, and duplicate expanded attribute names are input errors, not recoverable findings.

## Output and exit codes

The CLI emits one sorted-key JSON object to stdout. Success/audit reports include `tool`, `status`, `summary`, `findings`, and `findings_truncated`. Findings contain locations and counts by default. Error reports include a safe error code without echoing the input, path, original parser exception, or command arguments. `--help` is conventional human-readable text.

- 0: audit passes under the selected policy
- 1: complete audit found policy violations or reportable differences
- 2: invalid arguments, unreadable/non-UTF-8 input, malformed top-level input, or a hard resource limit; no partial pass is claimed

All input files must be regular files, UTF-8 encoded, and no larger than 8 MiB each. At most 100 findings are retained; `finding_count` still counts all findings, and truncation is explicit. JSON object members must be unique, and NaN/Infinity are not accepted as JSON numbers. JSON float tokens are read as `Decimal`. No input file is modified, no network is used, and no target code/configuration is executed. Reports are deterministic for the same input, flags, and runtime.

## Tool-specific limits and non-goals

128 element levels, 50,000 elements, 1,000 attributes per element, 200,000 attributes total, 10,000 namespace declarations; prefix/URI lengths at most 4,096 characters. At most 100 declarations and namespaces are displayed, with truncation indicators. Use a maintained Python/Expat runtime: these bounds and DTD rejection do not promise immunity to every parser vulnerability. XML input is UTF-8 text, not compressed or UTF-16 binary input. No XSD/DTD validation or XInclude processing.

## Python API

Import the local `tool.py` and call `audit(xml_text, require_namespaced_attributes=False, show_names=False)`. The return value is the same report dictionary used by the CLI; invalid supported inputs raise `InputError`. `parse_json(text)` is available for strict JSON parsing. File limits are enforced by `read_text(path)`; callers that construct Python objects directly must bound their own memory and provide the documented types. The audit API never writes files. Do not substitute untrusted Python evaluation for JSON parsing.

## Safe operation

Use only files the user authorized you to inspect. Keep reports local unless sharing is separately authorized. A passing result covers the documented checks only. Inspect selected findings against the original input before making changes in another system. No remediation, upload, service access, or production write is authorized by running this tool. Optional disclosure flags, where offered, must be deliberately selected.

## References

- https://www.w3.org/TR/xml-names/
- https://docs.python.org/3.12/library/xml.parsers.expat.html
- https://docs.python.org/3.12/library/xml.html
