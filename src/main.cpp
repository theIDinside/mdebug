/** LICENSE TEMPLATE */
#include "./utils/logger.h"
#include "event_queue.h"
#include "interface/dap/interface.h"
#include "mdb_config.h"
#include "mdbjs/mdbjs.h"
#include "tracer.h"
#include "utils/debugger_thread.h"
#include "utils/thread_pool.h"
#include <asm-generic/errno-base.h>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <fmt/core.h>
#include <linux/sched.h>
#include <poll.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utils/expected.h>

// std::mutex m;
std::string data;
bool ready = false;

mdb::Tracer *mdb::Tracer::sTracerInstance = nullptr;
mdb::js::AppScriptingInstance *mdb::Tracer::sScriptRuntime = nullptr;
JSContext *mdb::Tracer::sApplicationJsContext = nullptr;
int mdb::Tracer::sLastTraceEventTime = 0;

termios mdb::Tracer::sOriginalTty = {};
winsize mdb::Tracer::sTerminalWindowSize = {};
bool mdb::Tracer::sUsePTraceMe = true;
mdb::TracerProcess mdb::Tracer::sApplicationState = TracerProcess::Running;

mdb::ThreadPool *mdb::ThreadPool::sGlobalThreadPool = new mdb::ThreadPool{};

int
main(int argc, const char **argv)
{
  using mdb::logging::Logger;
  using mdb::logging::ProfilingLogger;
  signal(SIGTERM, [](int sig) {
    if (auto logger = ProfilingLogger::Instance(); logger && sig == SIGTERM) {
      logger->Shutdown();
    }
    mdb::EventSystem::Get().PushInternalEvent(mdb::TerminateDebugging{});
  });
  // Sets main thread id. It's static so subsequent calls from other threads should be fine.
  mdb::GetProcessId();
  mdb::EventSystem *eventSystem = mdb::EventSystem::Initialize();

  auto res = mdb::sys::ParseCommandLineArguments(argc, argv);
  if (!res.is_expected()) {
    auto &&err = res.error();
    switch (err.info) {
    case mdb::sys::CLIErrorInfo::BadArgValue:
      fmt::println("Bad CLI argument value");
      break;
    case mdb::sys::CLIErrorInfo::UnknownArgs:
      fmt::println("Unknown CLI argument");
      break;
    }
    exit(-1);
  }

  const mdb::sys::DebuggerConfiguration &config = res.value();

  const auto logEnvVar = std::getenv("LOG");
  Logger::ConfigureLogging(config.LogDirectory(), logEnvVar);

  std::span<const char *> args(argv, argc);
  namespace logging = mdb::logging;
  DBGLOG(core, "MDB CLI Arguments");
  for (const auto arg : args.subspan(1)) {
    DBGLOG(core, "{}", arg);
  }

  mdb::Tracer::Create(config);
  mdb::ThreadPool::GetGlobalPool()->Init(config.ThreadPoolSize());
  ProfilingLogger::ConfigureProfiling(config.LogDirectory());

  // spawn the UI thread that runs our UI loop
  bool uiThreadSetup = false;

  auto debugAdapterThread =
    mdb::DebuggerThread::SpawnDebuggerThread("IO-Thread", [&uiThreadSetup](std::stop_token &token) {
      mdb::ui::dap::DAP uiInterface{STDIN_FILENO, STDOUT_FILENO};
      mdb::Tracer::Get().SetUI(&uiInterface);
      uiThreadSetup = true;
      uiInterface.StartIOPolling(token);
    });

  while (!uiThreadSetup) {
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  }
  DBGLOG(core, "UI thread initialized and configured.");

  mdb::Tracer::InitializeDapSerializers();
  mdb::Tracer::InitInterpreterAndStartDebugger(std::move(debugAdapterThread), eventSystem);
  mdb::Tracer::Get().Shutdown();

  DBGLOG(core, "Exited...");
  return 0;
}