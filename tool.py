#!/usr/bin/env python3
"""Offline, read-only audit. Python 3.12+, standard library only."""
import argparse
import json
import math
import re
import stat
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 50000
MAX_FINDINGS = 100

class InputError(ValueError):
    """A safe, non-payload-bearing input error code."""

class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError("invalid_arguments")

def read_text(path):
    p = Path(path)
    if not stat.S_ISREG(p.stat().st_mode):
        raise InputError("regular_file_required")
    with p.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise InputError("file_size_limit")
    return data.decode("utf-8")

def reject_constant(value):
    raise InputError("non_finite_json_number")

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate_json_member")
        result[key] = value
    return result

def parse_json(text):
    try:
        result = json.loads(text, object_pairs_hook=unique_pairs,
                            parse_float=Decimal, parse_constant=reject_constant)
    except InputError:
        raise
    except (ValueError, RecursionError, InvalidOperation):
        raise InputError("invalid_json") from None
    stack, nodes = [(result, 0)], 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if depth > 128 or nodes > 200000:
            raise InputError("json_structure_limit")
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return result

class Report:
    def __init__(self, tool):
        self.tool, self.findings, self.count = tool, [], 0
    def add(self, code, **location):
        self.count += 1
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append(dict(code=code, **location))
    def finish(self, **summary):
        return {"tool": self.tool, "status": "fail" if self.count else "pass",
                "summary": dict(summary, finding_count=self.count),
                "findings": self.findings,
                "findings_truncated": self.count > len(self.findings)}

def emit_main(run):
    try:
        result = run()
        code = 1 if result["status"] == "fail" else 0
    except InputError as exc:
        result, code = {"tool": TOOL, "status": "error", "error": str(exc)}, 2
    except (OSError, UnicodeError):
        result, code = {"tool": TOOL, "status": "error", "error": "unreadable_utf8_input"}, 2
    except (ValueError, RecursionError, InvalidOperation):
        result, code = {"tool": TOOL, "status": "error", "error": "invalid_input"}, 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False))
    return code

TOOL = "xml-namespace-inventory"

from xml.parsers import expat

def audit(text, *, require_namespaced_attributes=False, show_names=False):
    report = Report(TOOL)
    declarations, namespace_ids, usage = [], {}, {}
    parser = expat.ParserCreate(namespace_separator="\x1f")
    depth = elements = attributes = unqualified = rebindings = 0
    bindings, scopes = {}, []
    pending = []
    def ns_id(uri):
        if uri not in namespace_ids:
            namespace_ids[uri] = len(namespace_ids) + 1
            usage[namespace_ids[uri]] = {"namespace_id": namespace_ids[uri], "elements": 0, "attributes": 0}
            if show_names:
                usage[namespace_ids[uri]]["uri"] = uri
        return namespace_ids[uri]
    def forbid(*args):
        raise InputError("dtd_or_entity_forbidden")
    parser.StartDoctypeDeclHandler = forbid
    parser.EntityDeclHandler = forbid
    parser.ExternalEntityRefHandler = forbid
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    declaration_count = 0
    def declaration(prefix, uri):
        nonlocal declaration_count
        declaration_count += 1
        if declaration_count > 10000 or len(prefix or "") > 4096 or len(uri or "") > 4096:
            raise InputError("namespace_declaration_limit")
        pending.append((prefix or "", uri or ""))
    parser.StartNamespaceDeclHandler = declaration
    def start(name, attrs):
        nonlocal depth, elements, attributes, unqualified, rebindings
        depth += 1
        elements += 1
        if depth > 128 or elements > MAX_RECORDS or len(attrs) > 1000:
            raise InputError("xml_structure_limit")
        old = []
        for prefix, uri in pending:
            previous = bindings.get(prefix)
            old.append((prefix, previous))
            if previous is not None and previous != uri:
                rebindings += 1
            bindings[prefix] = uri
            ident = ns_id(uri)
            if len(declarations) < 100:
                # Expat reports the start of the owning element, not the
                # individual xmlns attribute in a multiline opening tag.
                declarations.append({"line": parser.CurrentLineNumber, "namespace_id": ident,
                                     "default_namespace": prefix == "", "rebind": previous is not None and previous != uri})
                if show_names:
                    declarations[-1]["prefix"] = prefix
        scopes.append(old)
        pending.clear()
        uri = name.split("\x1f", 1)[0] if "\x1f" in name else ""
        usage[ns_id(uri)]["elements"] += 1
        attributes += len(attrs)
        if attributes > 200000:
            raise InputError("attribute_count_limit")
        for key in attrs:
            uri = key.split("\x1f", 1)[0] if "\x1f" in key else ""
            usage[ns_id(uri)]["attributes"] += 1
            if not uri:
                unqualified += 1
                if require_namespaced_attributes:
                    report.add("unqualified_attribute", line=parser.CurrentLineNumber, element=elements)
    def end(name):
        nonlocal depth
        for prefix, previous in reversed(scopes.pop()):
            if previous is None:
                bindings.pop(prefix, None)
            else:
                bindings[prefix] = previous
        depth -= 1
    parser.StartElementHandler, parser.EndElementHandler = start, end
    try:
        parser.Parse(text, True)
    except expat.ExpatError:
        raise InputError("malformed_xml") from None
    result = report.finish(elements=elements, attributes=attributes,
                           unqualified_attributes=unqualified,
                           namespace_count=len(namespace_ids), prefix_rebindings=rebindings,
                           namespace_declarations=declaration_count)
    result["namespaces"] = [usage[i] for i in sorted(usage)][:100]
    result["namespaces_truncated"] = len(usage) > 100
    result["declarations"] = declarations
    result["declarations_truncated"] = declaration_count > len(declarations)
    result["namespace_policy"] = ("URI and prefix values included" if show_names else "URI and prefix values redacted") + "; IDs follow first encounter; empty namespace included"
    return result

def run():
    parser = Parser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("--require-namespaced-attributes", action="store_true")
    parser.add_argument("--show-names", action="store_true", help="Opt in to namespace URI and prefix disclosure")
    args = parser.parse_args()
    return audit(read_text(args.input), require_namespaced_attributes=args.require_namespaced_attributes, show_names=args.show_names)

if __name__ == "__main__":
    sys.exit(emit_main(run))
