/*
 * NetWatch resident Llama runner (ExecuTorch, XNNPACK, CPU).
 *
 * llama_main loads the 1.1 GB model for every prompt (~15 s on a Pi 4). This keeps it loaded
 * and answers prompts over stdin/stdout:
 *
 *   request:   "<n>\n" followed by n bytes of prompt (already in the Llama 3 chat format)
 *   response:  generated text (prompt not echoed), then a "PyTorchObserver {json}" stats line,
 *              then the line "<<<NETWATCH_END>>>"
 *
 * It exits after --idle_exit_s seconds without a request, so the router gets its memory back.
 * Built next to llama_main by llm/build_runner.sh. Based on examples/models/llama/main.cpp (BSD).
 */

#include <executorch/examples/models/llama/runner/runner.h>
#include <gflags/gflags.h>
#include <poll.h>
#include <unistd.h>

#include <cstdio>
#include <iostream>
#include <string>

#if defined(ET_USE_THREADPOOL)
#include <executorch/extension/threadpool/threadpool.h>
#endif

DEFINE_string(model_path, "", "Model .pte file.");
DEFINE_string(tokenizer_path, "", "Tokenizer file.");
DEFINE_int32(cpu_threads, 2, "CPU threads (leave the rest to the router).");
DEFINE_int32(max_new_tokens, 140, "Tokens to generate per prompt.");
DEFINE_int32(idle_exit_s, 300, "Exit after this many idle seconds.");

static bool wait_for_input(int seconds) {
  struct pollfd p = {STDIN_FILENO, POLLIN, 0};
  return poll(&p, 1, seconds * 1000) > 0;
}

int main(int argc, char** argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
#if defined(ET_USE_THREADPOOL)
  if (FLAGS_cpu_threads > 0) {
    ::executorch::extension::threadpool::get_threadpool()->_unsafe_reset_threadpool(FLAGS_cpu_threads);
  }
#endif
  auto runner = example::create_llama_runner(FLAGS_model_path, FLAGS_tokenizer_path, std::vector<std::string>{}, 0.0f);
  if (runner == nullptr || runner->load() != executorch::runtime::Error::Ok) {
    fprintf(stderr, "netwatch_llm: failed to load model\n");
    return 1;
  }
  printf("<<<NETWATCH_READY>>>\n");
  fflush(stdout);

  std::string header;
  while (wait_for_input(FLAGS_idle_exit_s) && std::getline(std::cin, header)) {
    size_t n = 0;
    try {
      n = std::stoul(header);
    } catch (...) {
      continue;
    }
    std::string prompt(n, '\0');
    if (!std::cin.read(&prompt[0], static_cast<std::streamsize>(n))) {
      break;
    }
    executorch::extension::llm::GenerationConfig config{};
    config.temperature = 0.0f;
    config.echo = false;
    config.max_new_tokens = FLAGS_max_new_tokens;
    runner->reset();
    // TextLLMRunner itself prints each generated piece and, at the end, the "PyTorchObserver {json}"
    // stats line to stdout, so no callbacks are needed (they would print everything twice).
    auto err = runner->generate(prompt, config);
    if (err != executorch::runtime::Error::Ok) {
      printf("\nNETWATCH_ERROR generate failed\n");
    }
    printf("\n<<<NETWATCH_END>>>\n");
    fflush(stdout);
  }
  return 0;
}
