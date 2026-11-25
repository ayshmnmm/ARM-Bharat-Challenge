#!/usr/bin/env bash
# Prepare Llama 3.2 1B Instruct for ExecuTorch. Run on an x86-64 Linux machine (or WSL) with
# >= 16 GB RAM and ~20 GB free disk. NOT on the Pi: export needs far more memory than it has,
# and the Pi must not download from the internet.
#
# Prerequisite: accept Meta's licence at https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct
# and log in once with:  hf auth login
#
# Produces in ./llm-out:
#   llama3_2_1b_instruct_8da4w.pte                 our own export (8-bit act / 4-bit weight, XNNPACK)
#   Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte   Meta's SpinQuant export (for the benchmark comparison)
#   tokenizer.model
# then copy to the Pi with:  bash llm/push_to_pi.sh
set -euo pipefail

ET_VERSION="1.5.1"
TORCH_VERSION="2.14.0"
OUT="${OUT:-$PWD/llm-out}"
VENV="${VENV:-$PWD/.export-venv}"
MAX_SEQ=1024   # prompt (~300 tokens) + answer (<= 256 tokens), with headroom; keeps the KV cache small

mkdir -p "$OUT"
if [[ ! -x "$VENV/bin/python" ]]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --upgrade pip
  # CPU-only PyTorch (PyPI's default is a ~2.5 GB CUDA build that export doesn't need).
  "$VENV/bin/pip" install -q --index-url https://download.pytorch.org/whl/cpu "torch==$TORCH_VERSION"
  "$VENV/bin/pip" install -q --uploaded-prior-to 2026-11-02T00:00:00Z \
    "executorch==$ET_VERSION" "huggingface_hub[cli]"
fi
PY="$VENV/bin/python"
HF="$VENV/bin/hf"

echo "== Download Meta checkpoint (original/ format)"
"$HF" download meta-llama/Llama-3.2-1B-Instruct --include "original/*" --local-dir "$OUT/hf"
cp "$OUT/hf/original/tokenizer.model" "$OUT/tokenizer.model"

echo "== Export: 8da4w (group 32), 4-bit embeddings, KV cache + SDPA, XNNPACK delegate"
(cd "$OUT" && "$PY" -m executorch.extension.llm.export.export_llm \
  base.model_class=llama3_2 \
  base.checkpoint="$OUT/hf/original/consolidated.00.pth" \
  base.params="$OUT/hf/original/params.json" \
  base.metadata='"{\"get_bos_id\":128000, \"get_eos_ids\":[128009, 128001]}"' \
  model.use_kv_cache=True \
  model.use_sdpa_with_kv_cache=True \
  model.dtype_override=fp32 \
  export.max_seq_length=$MAX_SEQ \
  export.max_context_length=$MAX_SEQ \
  export.output_name=llama3_2_1b_instruct_8da4w.pte \
  quantization.qmode=8da4w \
  quantization.group_size=32 \
  quantization.embedding_quantize=\'4,32\' \
  backend.xnnpack.enabled=True \
  backend.xnnpack.extended_ops=True)

echo "== Download Meta's SpinQuant ExecuTorch export (comparison model)"
"$HF" download executorch-community/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8-ET \
  Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte --local-dir "$OUT"

sha256sum "$OUT"/*.pte "$OUT/tokenizer.model" | tee "$OUT/SHA256SUMS"
ls -la "$OUT"/*.pte "$OUT/tokenizer.model"
echo "Next: bash llm/push_to_pi.sh"
