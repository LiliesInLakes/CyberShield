import sys
sys.path.insert(0, r"D:\BOI\L1")
from engines.jadx_analyze import _scan_sources, _is_library
from pathlib import Path

src = Path(r"D:\BOI\L1\artifacts\b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b91f902d194a4\jadx_src")
app, lib = _scan_sources(src)
print("app:", len(app), "lib:", len(lib))
for f in app[:5]:
    print("APP", f.location)
for f in lib[:3]:
    print("LIB", f.location)
p = src / "sources" / "com" / "android" / "insecurebankv2" / "ChangePassword.java"
print("exists:", p.exists(), "is_lib:", _is_library(str(p.relative_to(src))))
