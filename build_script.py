import subprocess, sys, os, shutil, platform

# 路径自动定位到脚本所在目录（无需手动修改）
HERE = os.path.dirname(os.path.abspath(__file__))
src  = os.path.join(HERE, "ecat_pdo_analyzer.py")
dist = os.path.join(HERE, "dist")
bld  = os.path.join(HERE, "build_tmp")

# ── Python 路径（跨平台）─────────────────────────────────────
_sys = platform.system()
if _sys == "Windows":
    py = os.path.join(HERE, "build_env", "Scripts", "python.exe")
else:
    # Linux / macOS: build_env/bin/python3  或 fallback 到系统 Python
    for _cand in [
        os.path.join(HERE, "build_env", "bin", "python3"),
        os.path.join(HERE, "build_env", "bin", "python"),
    ]:
        if os.path.isfile(_cand):
            py = _cand; break
    else:
        py = sys.executable  # 使用当前 Python

if not os.path.isfile(py):
    print(f"[警告] 未找到 build_env Python ({py})，使用系统 Python: {sys.executable}")
    py = sys.executable

# ── 清理旧产物 ────────────────────────────────────────────────
os.makedirs(dist, exist_ok=True)
if os.path.exists(bld):
    shutil.rmtree(bld)
# 删除旧的可执行文件（Windows .exe；Linux/macOS 无后缀）
for f in os.listdir(dist):
    fp = os.path.join(dist, f)
    if os.path.isfile(fp) and (f.endswith(".exe") or not os.path.splitext(f)[1]):
        os.remove(fp)

# ── PyInstaller 命令 ──────────────────────────────────────────
cmd = [
    py, "-m", "PyInstaller",
    "--onefile",
    "--windowed" if _sys in ("Windows", "Darwin") else "--noconsole",
    "--name", "EtherCAT_PDO分析工具",
    "--distpath", dist,
    "--workpath", bld,
    "--specpath", bld,
    "--hidden-import=matplotlib.backends.backend_tkagg",
    "--hidden-import=matplotlib.backends._backend_tk",
    "--hidden-import=tkinter",
    "--hidden-import=tkinter.ttk",
    "--hidden-import=numpy",
    "--hidden-import=xml.etree.ElementTree",
    "--collect-all=matplotlib",
    src,
]

print(f"Building on {_sys} using: {py}")
r = subprocess.run(cmd)
sys.exit(r.returncode)
