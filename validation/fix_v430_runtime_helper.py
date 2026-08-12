from pathlib import Path

path = Path("validation/apply_v430_runtime_controls.py")
text = path.read_text(encoding="utf-8")
old = '''if runtime.count(old_integrator_start) != 1:\n    raise SystemExit("mesh_runtime.py: could not locate integrator start")\nruntime = runtime.replace(old_integrator_start, new_integrator_start, 1)\n'''
new = '''integrator_start = runtime.index("    def _execute_integrator(self, node: dict[str, Any]) -> dict[str, Any]:")\nintegrator_end = runtime.index("    def _execute(self, node: dict[str, Any]) -> dict[str, Any]:", integrator_start)\nintegrator_section = runtime[integrator_start:integrator_end]\nif integrator_section.count(old_integrator_start) != 1:\n    raise SystemExit("mesh_runtime.py: could not locate integrator start")\nintegrator_section = integrator_section.replace(old_integrator_start, new_integrator_start, 1)\nruntime = runtime[:integrator_start] + integrator_section + runtime[integrator_end:]\n'''
if text.count(old) != 1:
    raise SystemExit("Could not locate integrator-start helper block")
text = text.replace(old, new)

old = '''if runtime.count(old_integrator_error) != 1:\n    raise SystemExit("mesh_runtime.py: could not locate integrator failure block")\nruntime = runtime.replace(old_integrator_error, new_integrator_error, 1)\n'''
new = '''integrator_start = runtime.index("    def _execute_integrator(self, node: dict[str, Any]) -> dict[str, Any]:")\nintegrator_end = runtime.index("    def _execute(self, node: dict[str, Any]) -> dict[str, Any]:", integrator_start)\nintegrator_section = runtime[integrator_start:integrator_end]\nif integrator_section.count(old_integrator_error) != 1:\n    raise SystemExit("mesh_runtime.py: could not locate integrator failure block")\nintegrator_section = integrator_section.replace(old_integrator_error, new_integrator_error, 1)\nruntime = runtime[:integrator_start] + integrator_section + runtime[integrator_end:]\n'''
if text.count(old) != 1:
    raise SystemExit("Could not locate integrator-error helper block")
text = text.replace(old, new)

old = '''if runtime.count(old_combined_meta) != 1:\n    raise SystemExit("mesh_runtime.py: could not locate combined patch metadata")\nruntime = runtime.replace(old_combined_meta, new_combined_meta, 1)\n'''
new = '''integrator_start = runtime.index("    def _execute_integrator(self, node: dict[str, Any]) -> dict[str, Any]:")\nintegrator_end = runtime.index("    def _execute(self, node: dict[str, Any]) -> dict[str, Any]:", integrator_start)\nintegrator_section = runtime[integrator_start:integrator_end]\nif integrator_section.count(old_combined_meta) != 1:\n    raise SystemExit("mesh_runtime.py: could not locate combined patch metadata")\nintegrator_section = integrator_section.replace(old_combined_meta, new_combined_meta, 1)\nruntime = runtime[:integrator_start] + integrator_section + runtime[integrator_end:]\n'''
if text.count(old) != 1:
    raise SystemExit("Could not locate combined-metadata helper block")
text = text.replace(old, new)

old = '''if runtime.count(old_check_start) != 1:\n    raise SystemExit("mesh_runtime.py: could not locate check-runner start")\nruntime = runtime.replace(old_check_start, new_check_start, 1)\n'''
new = '''check_start = runtime.index("    def _execute_check_runner(self, node: dict[str, Any]) -> dict[str, Any]:")\ncheck_end = runtime.index("    def _execute_integrator(self, node: dict[str, Any]) -> dict[str, Any]:", check_start)\ncheck_section = runtime[check_start:check_end]\nif check_section.count(old_check_start) != 1:\n    raise SystemExit("mesh_runtime.py: could not locate check-runner start")\ncheck_section = check_section.replace(old_check_start, new_check_start, 1)\nruntime = runtime[:check_start] + check_section + runtime[check_end:]\n'''
if text.count(old) != 1:
    raise SystemExit("Could not locate check-start helper block")
text = text.replace(old, new)

old = '''if runtime.count(old_check_artifact) != 1:\n    raise SystemExit("mesh_runtime.py: could not locate check artifact block")\nruntime = runtime.replace(old_check_artifact, new_check_artifact, 1)\n'''
new = '''check_start = runtime.index("    def _execute_check_runner(self, node: dict[str, Any]) -> dict[str, Any]:")\ncheck_end = runtime.index("    def _execute_integrator(self, node: dict[str, Any]) -> dict[str, Any]:", check_start)\ncheck_section = runtime[check_start:check_end]\nif check_section.count(old_check_artifact) != 1:\n    raise SystemExit("mesh_runtime.py: could not locate check artifact block")\ncheck_section = check_section.replace(old_check_artifact, new_check_artifact, 1)\nruntime = runtime[:check_start] + check_section + runtime[check_end:]\n'''
if text.count(old) != 1:
    raise SystemExit("Could not locate check-artifact helper block")
text = text.replace(old, new)

path.write_text(text, encoding="utf-8")
