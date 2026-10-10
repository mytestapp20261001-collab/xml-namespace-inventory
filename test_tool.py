import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(HERE.name.replace("-", "_"), HERE / "tool.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)

class CommonTests(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, str(HERE / "tool.py"), *args], cwd=HERE,
                              capture_output=True, text=True, timeout=10)
    def test_cli_pass(self):
        result = self.cli("examples/" + PASS, *ARGS)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "pass")
        self.assertEqual(result.stderr, "")
    def test_cli_fail(self):
        result = self.cli("examples/" + FAIL, *ARGS)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "fail")
    def test_cli_malformed(self):
        result = self.cli("examples/" + MALFORMED, *ARGS)
        self.assertEqual(result.returncode, MALFORMED_CODE, result.stdout + result.stderr)
        self.assertIn(json.loads(result.stdout)["status"], ("fail", "error"))
    def test_cli_missing_file(self):
        result = self.cli("nonexistent-input", *ARGS)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["error"], "unreadable_utf8_input")
    def test_cli_invalid_arguments_are_redacted(self):
        result = self.cli("--unrecognized-secret-value")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["error"], "invalid_arguments")
        self.assertNotIn("unrecognized-secret-value", result.stdout + result.stderr)
    def test_cli_help(self):
        result = self.cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout)
    def test_cli_stability(self):
        a = self.cli("examples/" + FAIL, *ARGS)
        b = self.cli("examples/" + FAIL, *ARGS)
        self.assertEqual(a.stdout, b.stdout)
    def test_file_limit_and_utf8(self):
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"x" * (tool.MAX_BYTES + 1))
            with self.assertRaises(tool.InputError):
                tool.read_text(path)
            path.write_bytes(b"\xff")
            with self.assertRaises(UnicodeDecodeError):
                tool.read_text(path)
    def test_json_parser_safety(self):
        for text in ('{"x":1,"x":2}', '[NaN]', '[' * 130 + '0' + ']' * 130):
            with self.subTest(text=text[:20]), self.assertRaises(tool.InputError):
                tool.parse_json(text)
    def test_report_cap_preserves_count(self):
        report = tool.Report("test")
        for i in range(101):
            report.add("sample", record=i)
        result = report.finish()
        self.assertEqual(len(result["findings"]), 100)
        self.assertEqual(result["summary"]["finding_count"], 101)
        self.assertTrue(result["findings_truncated"])

    def test_adversarial_cli_and_read_only_corpus(self):
        samples = ['', 'null', 'true', '0', '[]', '{}', '[null]', '[true]', '[1]',
                   '["NaN"]', '[{}]', '[[]]', '{"x":1,"x":2}',
                   '[1e99999999999999999999999999]', '[NaN]', '[Infinity]',
                   '"\\ud800"', '["\\ud800"]', '{', '[', '["a","b"]',
                   '[1e-99999999999999999999999999]']
        before = {path: path.read_bytes() for path in (HERE / 'examples').iterdir()}
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            path = Path(directory) / 'input.txt'
            for sample in samples:
                with self.subTest(sample=sample):
                    path.write_text(sample, encoding='utf-8')
                    result = self.cli(str(path), *ARGS)
                    self.assertIn(result.returncode, (0, 1, 2), result.stderr)
                    self.assertEqual(result.stderr, '')
                    self.assertIn(json.loads(result.stdout)['status'], ('pass','fail','error'))
                    self.assertEqual(path.read_text(encoding='utf-8'), sample)
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)

PASS = 'pass.xml'
FAIL = 'fail.xml'
MALFORMED = 'malformed.xml'
MALFORMED_CODE = 2
ARGS = ['--require-namespaced-attributes']

class AuditTests(unittest.TestCase):
    def test_default_namespace_not_applied_to_attributes(self):
        result=tool.audit('<r xmlns="urn:a" id="1"/>')
        self.assertEqual(result['summary']['unqualified_attributes'],1)
        self.assertEqual(result['summary']['namespace_count'],2)
        self.assertEqual(result['status'],'pass')
    def test_required_qualified_attributes(self):
        result=tool.audit('<r xmlns="urn:a" id="1"/>',require_namespaced_attributes=True)
        self.assertEqual(result['status'],'fail')
    def test_namespace_aliases_share_id(self):
        result=tool.audit('<r xmlns:a="urn:x" xmlns:b="urn:x"><a:x b:y="1"/></r>')
        self.assertEqual(result['declarations'][0]['namespace_id'],result['declarations'][1]['namespace_id'])
    def test_scope_rebinding_restored(self):
        result=tool.audit('<r xmlns:a="urn:a"><x xmlns:a="urn:b"/><y xmlns:a="urn:a"/></r>')
        self.assertEqual(result['summary']['prefix_rebindings'],1)
    def test_dtd_external_entity_rejected(self):
        for text in ('<!DOCTYPE r><r/>','<!DOCTYPE r SYSTEM "https://example.invalid/dtd"><r/>', '<!DOCTYPE r [<!ENTITY x "data">]><r>&x;</r>'):
            with self.assertRaisesRegex(tool.InputError,'dtd_or_entity_forbidden'): tool.audit(text)
    def test_predefined_and_numeric_refs_allowed(self):
        self.assertEqual(tool.audit('<r>&amp;&#65;</r>')['status'],'pass')
    def test_xml_builtin_namespace(self):
        result=tool.audit('<r xml:lang="en"/>',require_namespaced_attributes=True)
        self.assertEqual(result['status'],'pass')
    def test_malformed_duplicate_unbound(self):
        for text in ('<r>','<r x="1" x="2"/>','<a:r/>',''):
            with self.assertRaises(tool.InputError): tool.audit(text)
    def test_dtd_marker_in_comment_is_harmless(self):
        self.assertEqual(tool.audit('<!-- <!DOCTYPE fake> --><r/>')['status'],'pass')
    def test_depth_bound(self):
        with self.assertRaises(tool.InputError): tool.audit('<r>'*129+'</r>'*129)
    def test_names_opt_in(self):
        result=tool.audit('<r xmlns:a="urn:x"><a:z/></r>',show_names=True)
        self.assertEqual(result['namespaces'][0]['uri'],'urn:x')
        self.assertEqual(result['declarations'][0]['prefix'],'a')
    def test_namespace_uri_limit(self):
        with self.assertRaises(tool.InputError): tool.audit('<r xmlns="'+ 'x'*4097 +'"/>')
    def test_values_redacted(self):
        result=tool.audit('<r xmlns="urn:SUPERSECRET" a="SUPERSECRET">SUPERSECRET</r>')
        self.assertNotIn('SUPERSECRET',json.dumps(result))

    def test_multiline_opening_tag_reports_element_start_line(self):
        text = '<!-- leading line -->\n<root\n xmlns:a="urn:a"\n xmlns:b="urn:b"\n plain="value">\n<a:child/>\n</root>'
        report = tool.audit(text, require_namespaced_attributes=True)
        self.assertEqual([d['line'] for d in report['declarations']], [2, 2])
        self.assertEqual(report['findings'][0]['line'], 2)
        self.assertEqual(report['findings'][0]['code'], 'unqualified_attribute')
        self.assertEqual(report['summary']['namespace_declarations'], 2)

if __name__ == '__main__': unittest.main()
