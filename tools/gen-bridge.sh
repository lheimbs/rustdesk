#!/bin/bash
# Generate the flutter_rust_bridge files (git-ignored) the Flutter build needs.
#
# Same approach as .github/workflows/bridge.yml (codegen 1.80.1, bridge generated with Flutter 3.22.3,
# app built with Flutter 3.24.5) plus fixes for a libclang newer than the one CI uses: with libclang 22
# the pinned ffigen emits `typedef bool = ...`, `Pointer<bool>` parameters and a wrong
# `store_dart_post_cobject` type. The fixes below make the generated Dart compile; they are no-ops
# on output that is already correct.
#
# needs: flutter_rust_bridge_codegen 1.80.1 and cargo-expand 1.0.95 (cargo install --locked ...),
#        Flutter 3.22.3 and 3.24.5 (mise: flutter@3.22.3, flutter@3.24.5), LIBCLANG_PATH if needed.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH=$HOME/.cargo/bin:$HOME/.local/share/mise/shims:$PATH
F322=$(mise where flutter@3.22.3)/bin

cp flutter/pubspec.yaml /tmp/handover-pubspec.yaml.orig
trap 'cp /tmp/handover-pubspec.yaml.orig flutter/pubspec.yaml; git checkout -q flutter/pubspec.lock' EXIT
sed -i -e 's/extended_text: 14.0.0/extended_text: 13.0.0/g' flutter/pubspec.yaml
(cd flutter && PATH=$F322:$PATH flutter pub get)
PATH=$F322:$PATH flutter_rust_bridge_codegen --llvm-compiler-opts=-std=gnu11 \
  --rust-input ./src/flutter_ffi.rs --dart-output ./flutter/lib/generated_bridge.dart \
  --c-output ./flutter/macos/Runner/bridge_generated.h

python3 - <<'PY'
import re
p = 'flutter/lib/generated_bridge.dart'
s = open(p).read()
s = re.sub(r'^typedef bool = ffi\.NativeFunction<[^\n]*\n', '', s, flags=re.M)
s = s.replace('ffi.Pointer<bool>', 'ffi.Pointer<ffi.Bool>')
s = re.sub(r'_lookup<\s*ffi\.NativeFunction<.*?>>\(', lambda m: m.group(0).replace('ffi.Pointer<ffi.Bool>', 'ffi.Bool'), s, flags=re.S)
s = re.sub(r'\.asFunction<.*?>\(\)', lambda m: m.group(0).replace('ffi.Pointer<ffi.Bool>', 'bool'), s, flags=re.S)
s = s.replace('ffi.Pointer<ffi.Bool>', 'bool')
s = s.replace('ffi.NativeFunction<ffi.Bool Function(DartPort', 'ffi.NativeFunction<ffi.Uint8 Function(DartPort')
s = s.replace('  void store_dart_post_cobject(\n    int ptr,\n  ) {', '  void store_dart_post_cobject(\n    DartPostCObject ptr,\n  ) {')
s = s.replace("_lookup<ffi.NativeFunction<ffi.Void Function(ffi.Int)>>(\n          'store_dart_post_cobject');", "_lookup<ffi.NativeFunction<ffi.Void Function(DartPostCObject)>>(\n          'store_dart_post_cobject');")
s = s.replace('_store_dart_post_cobjectPtr.asFunction<void Function(int)>();', '_store_dart_post_cobjectPtr.asFunction<void Function(DartPostCObject)>();')
open(p, 'w').write(s)
PY
(cd flutter && PATH=$F322:$PATH dart run build_runner build --delete-conflicting-outputs)
echo "bridge generated: src/bridge_generated*.rs flutter/lib/generated_bridge*.dart"
