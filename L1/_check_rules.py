"""Fix unreferenced hex strings in YARA rules then verify compilation."""
import yara, re
from pathlib import Path

p = Path(__file__).resolve().parent / "yara_templates"
index = p / "index.yar"

while True:
    try:
        rules = yara.compile(filepath=str(index))
        print(f"OK: {len(rules)} rules compiled")
        break
    except yara.SyntaxError as e:
        msg = str(e)
        m = re.search(r'(.+\.yar)\((\d+)\):\s*unreferenced string "\$(\w+)"', msg)
        if not m:
            print(f"Unhandled: {e}")
            break
        fname, lineno, sname = m.group(1), int(m.group(2)), m.group(3)
        fpath = p / fname
        text = fpath.read_text()
        lines = text.split("\n")
        pat = re.compile(r'^\s+\$' + re.escape(sname) + r'\s*=')
        new_lines = [line for line in lines if not pat.match(line)]
        if len(new_lines) != len(lines):
            fpath.write_text("\n".join(new_lines))
            print(f"Fixed: {fname} removed ${sname}")
        else:
            print(f"Could not find ${sname} in {fname}")
            break
