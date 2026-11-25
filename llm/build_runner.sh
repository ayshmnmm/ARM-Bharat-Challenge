#!/usr/bin/env bash
# Build ExecuTorch's Llama runner (llama_main, CPU + XNNPACK) natively on the Pi.
#
# Router-safe: lowest CPU priority, 2 parallel jobs, idle I/O class. PyTorch is installed into a
# build-only venv (ExecuTorch's kernel codegen imports torchgen); it is never used at runtime.
# Takes a few hours on a Pi 4. Resumable: re-running continues an interrupted build.
#
#   bash llm/build_runner.sh            # source in ~/src/executorch (v1.5.1)
set -euo pipefail

ET_VERSION="v1.5.1"
TORCH_VERSION="2.14.0"     # ExecuTorch 1.5.1's torch_pin.py
SRC="${ET_SRC:-$HOME/src/executorch}"
VENV="${ET_BUILD_VENV:-$HOME/src/et-build-venv}"
OUT="$(cd "$(dirname "$0")" && pwd)/artifacts"
SERVER_SRC="$(cd "$(dirname "$0")" && pwd)/server/netwatch_llm.cpp"
JOBS="${JOBS:-2}"

run() { nice -n 19 ionice -c3 "$@"; }

if [[ ! -d "$SRC" ]]; then
  git clone --branch "$ET_VERSION" --depth 1 https://github.com/pytorch/executorch.git "$SRC"
fi
cd "$SRC"
[[ "$(git describe --tags)" == "$ET_VERSION" ]] || { echo "expected $ET_VERSION in $SRC" >&2; exit 1; }
# CUTLASS (a GPU library nested in torchao) is not needed for a CPU build; skip it if it failed.
git -c submodule."third-party/ao".update=none submodule update --init --recursive --depth 1 --jobs 2 || true

if ! "$VENV/bin/python" -c "import torchgen" 2>/dev/null; then
  python3 -m venv "$VENV"
  # Debian's bundled pip predates --uploaded-prior-to
  PIP_CONFIG_FILE=/dev/null "$VENV/bin/pip" install -q --index-url https://pypi.org/simple --upgrade pip
  # CPU-only PyTorch from pytorch.org: PyPI's aarch64 wheel drags in ~2 GB of CUDA libraries.
  # (That index has no upload dates for --uploaded-prior-to; the exact pin does the same job.)
  PIP_CONFIG_FILE=/dev/null "$VENV/bin/pip" install -q --resume-retries 20 \
    --index-url https://download.pytorch.org/whl/cpu "torch==$TORCH_VERSION"
  PIP_CONFIG_FILE=/dev/null "$VENV/bin/pip" install -q --resume-retries 20 --index-url https://pypi.org/simple \
    --uploaded-prior-to 2026-11-02T00:00:00Z pyyaml ruamel.yaml typing-extensions
fi
export PATH="$VENV/bin:$PATH"
export CMAKE_BUILD_PARALLEL_LEVEL="$JOBS"

echo "== $(date) building ExecuTorch core (llm-release preset)"
run cmake --workflow --preset llm-release
# NetWatch's resident runner (llm/server/netwatch_llm.cpp) is built as a second target of the llama
# example: same libraries as llama_main. The CMake lines are appended once, marked, to the local clone.
if ! grep -q "NETWATCH_LLM" examples/models/llama/CMakeLists.txt; then
  cat >> examples/models/llama/CMakeLists.txt <<CMAKE

# NETWATCH_LLM: resident runner for NetWatch (added by netwatch/llm/build_runner.sh)
add_executable(netwatch_llm $SERVER_SRC)
target_include_directories(netwatch_llm PUBLIC \${_common_include_directories})
target_link_libraries(netwatch_llm PUBLIC llama_runner \${link_libraries})
target_compile_options(netwatch_llm PUBLIC \${_common_compile_options})
set_target_properties(netwatch_llm PROPERTIES LINK_FLAGS "-Wl,-rpath='\$ORIGIN'")
CMAKE
fi
echo "== $(date) building llama_main and netwatch_llm"
(cd examples/models/llama && run cmake --workflow --preset llama-release)
run cmake --build cmake-out/examples/models/llama --target netwatch_llm -j "$JOBS"

mkdir -p "$OUT"
cp cmake-out/examples/models/llama/llama_main "$OUT/llama_main"
cp cmake-out/examples/models/llama/netwatch_llm "$OUT/netwatch_llm"
# llama_main links libllama_runner.so; its RUNPATH includes $ORIGIN, so ship the library beside it.
cp cmake-out/examples/models/llama/runner/libllama_runner.so "$OUT/libllama_runner.so"
strip "$OUT/llama_main" "$OUT/netwatch_llm" "$OUT/libllama_runner.so" || true
"$OUT/llama_main" --help 2>&1 | head -5 || true
echo "== $(date) done: $OUT/llama_main ($(du -h "$OUT/llama_main" | cut -f1))"
