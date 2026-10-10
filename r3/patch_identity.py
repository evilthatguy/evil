from pathlib import Path
import os
import re

PACKAGE = os.environ.get('KSU_PACKAGE_NAME', 'app.nca764574fc.tools')
DAEMON = 'libnovabridge.so'
assert re.fullmatch(r'app\.[a-z][a-z0-9]+\.tools', PACKAGE)

def replace_once(path, old, new):
    path = Path(path)
    text = path.read_text()
    assert text.count(old) == 1, f'Source mismatch: {path}: {old!r}'
    path.write_text(text.replace(old, new, 1))

replacements = [
    ('me.weishu.kernelsu', PACKAGE),
    ('me/weishu/kernelsu', PACKAGE.replace('.', '/')),
    ('me_weishu_kernelsu', PACKAGE.replace('.', '_')),
    ('KernelSUApplication', 'RuntimeApplication'),
    ('AppZygotePreload', 'RuntimePreload'),
    ('MainActivity', 'DashboardActivity'),
    ('libksud.so', DAEMON),
    ('libadbroot.so', 'libnovalink.so'),
    ('System.loadLibrary("kernelsu")', 'System.loadLibrary("novacore")'),
]

# Rewrite every manager reference, including AIDL imports, Manifest and JNI.
for path in Path('ksu/manager').rglob('*'):
    if not path.is_file():
        continue
    try:
        original = path.read_text()
    except UnicodeDecodeError:
        continue
    text = original
    for old, new in replacements:
        text = text.replace(old, new)
    if text != original:
        path.write_text(text)

# AIDL requires a directory matching its package; Java requires its public
# class name to match the file. Kotlin filenames are also renamed for clarity.
for kind in ('java', 'aidl'):
    root = Path(f'ksu/manager/app/src/main/{kind}')
    old = root / 'me/weishu/kernelsu'
    new = root / PACKAGE.replace('.', '/')
    new.parent.mkdir(parents=True, exist_ok=True)
    old.rename(new)
    for path in list(new.rglob('*')):
        if path.is_file():
            name = path.name
            for before, after in replacements[3:6]:
                name = name.replace(before, after)
            if name != path.name:
                path.rename(path.with_name(name))

replace_once('ksu/manager/app/build.gradle.kts',
             'abiFilters += listOf("arm64-v8a", "x86_64")',
             'abiFilters += listOf("arm64-v8a")')
replace_once('ksu/manager/app/src/main/cpp/CMakeLists.txt',
             'target_include_directories(kernelsu PRIVATE .)',
             'set_target_properties(kernelsu PROPERTIES OUTPUT_NAME "novacore")\n\n'
             'target_include_directories(kernelsu PRIVATE .)')
replace_once('ksu/manager/app/src/main/cpp/CMakeLists.txt',
             'add_library(adbroot SHARED adbroot.cc)',
             'add_library(adbroot SHARED adbroot.cc)\n'
             'set_target_properties(adbroot PROPERTIES OUTPUT_NAME "novalink")')

# The upstream repacker must inject the daemon under the name the app loads.
path = Path('ksu/repack_apk.py')
text = path.read_text()
assert text.count('libksud.so') >= 5
path.write_text(text.replace('libksud.so', DAEMON))

# Original late-load starts a hardcoded component, separate from the APK.
replace_once('ksu/userspace/ksud/src/late_load.rs',
             'me.weishu.kernelsu.ui.MainActivity', PACKAGE + '.ui.DashboardActivity')
replace_once('ksu/userspace/ksud/build.rs',
             'KSU_PACKAGE_NAME=me.weishu.kernelsu', 'KSU_PACKAGE_NAME=' + PACKAGE)

repo = 'ghost/app/src/main/kotlin/com/ghostlock/app/data/AndroidGhostlockRepository.kt'
replace_once(repo,
             'val packages = listOf("me.weishu.kernelsu.pr", "me.weishu.kernelsu", "com.resukisu.resukisu", "com.kowx712.supermanager")',
             f'val packages = listOf("{PACKAGE}")')
replace_once(repo, 'File(appInfo.nativeLibraryDir, "libksud.so")',
             f'File(appInfo.nativeLibraryDir, "{DAEMON}")')

manifest = 'ghost/app/src/main/AndroidManifest.xml'
for old in ('me.weishu.kernelsu.pr', 'me.weishu.kernelsu', 'com.resukisu.resukisu', 'com.kowx712.supermanager'):
    replace_once(manifest, f'        <package android:name="{old}" />\n', '')
replace_once(manifest, '<queries>', f'<queries>\n        <package android:name="{PACKAGE}" />')
replace_once(manifest, 'android:label="@string/app_name"', 'android:label="GhostLock Trial R2"')
replace_once(manifest, 'android:name=".ui.MainActivity"', 'android:name=".ui.ControlActivity"')
replace_once('ghost/app/src/main/kotlin/com/ghostlock/app/ui/MainActivity.kt',
             'class MainActivity : ComponentActivity()', 'class ControlActivity : ComponentActivity()')
Path('ghost/app/src/main/kotlin/com/ghostlock/app/ui/MainActivity.kt').rename(
    'ghost/app/src/main/kotlin/com/ghostlock/app/ui/ControlActivity.kt')
replace_once('ghost/app/build.gradle.kts',
             'applicationId = "com.ghostlock.app"', 'applicationId = "com.ghostlock.trial"')

# Keep the proven exploit/profile and root script. Replace only its fallback
# discovery, as in the previously working trial.
path = Path('ghost/src/core/attack/ops.cpp')
text = path.read_text()
start = text.index(r'            "if [ ! -x \"$KSUD\" ]; then\n"')
end = text.index(r'            "echo \"[*] ksud=$KSUD\" >>\"$LOG\"\n"', start)
blocks = text[start:end].splitlines(keepends=True)
assert len(blocks) == 14 and 'me.weishu.kernelsu.pr' in blocks[1]
replacement = ''.join(blocks[:3]).replace(
    '*/me.weishu.kernelsu.pr*/lib/arm64/libksud.so',
    f'*/{PACKAGE}-*/lib/arm64/{DAEMON}')
path.write_text(text[:start] + replacement + text[end:])

# Fail before compiling if package, Java/JNI, preload, or executable paths
# remain inconsistent. These assertions check the cross-language boundaries.
base = Path('ksu/manager/app/src/main/java') / PACKAGE.replace('.', '/')
assert (base / 'RuntimeApplication.kt').is_file()
assert (base / 'magica/RuntimePreload.java').is_file()
assert (base / 'ui/DashboardActivity.kt').is_file()
jni = Path('ksu/manager/app/src/main/cpp/jni.cc').read_text()
assert 'Java_' + PACKAGE.replace('.', '_') + '_Natives_getVersion' in jni
assert 'Java_' + PACKAGE.replace('.', '_') + '_magica_RuntimePreload_forkDontCareAndExecKsud' in jni
assert PACKAGE.replace('.', '/') + '/Natives$Profile' in jni
assert 'System.loadLibrary("novacore")' in (base / 'Natives.kt').read_text()
assert 'System.loadLibrary("novacore")' in (base / 'magica/RuntimePreload.java').read_text()
for root in (Path('ksu/manager/app/src'),):
    for path in root.rglob('*'):
        if not path.is_file():
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        for old in ('me.weishu.kernelsu', 'me/weishu/kernelsu', 'me_weishu_kernelsu',
                    'KernelSUApplication', 'AppZygotePreload', 'libksud.so', 'libadbroot.so'):
            assert old not in text, f'Unpatched identity in {path}: {old}'
assert DAEMON in (base / 'ui/util/KsuCli.kt').read_text()
assert PACKAGE + '.ui.DashboardActivity' in Path('ksu/userspace/ksud/src/late_load.rs').read_text()
print('PASS: source identity, AIDL, JNI, preload, daemon, launcher and GhostLock discovery')
