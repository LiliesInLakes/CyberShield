import json, sys, glob
from pathlib import Path

artifacts = Path(r'D:\BOI\L1\artifacts')
for d in sorted(artifacts.iterdir()):
    if not d.is_dir():
        continue
    aj = d / 'analysis.json'
    if not aj.exists():
        continue
    data = json.loads(aj.read_text())
    s = data['summary']
    print(f"\n=== {d.name[:12]} ===")
    print(json.dumps(s, indent=2))
    for f in data['findings'][:5]:
        print(f"  [{f['severity']}] {f['category']}: {f['evidence'][:130]}")
    if len(data['findings']) > 5:
        print(f"  ... and {len(data['findings'])-5} more")
