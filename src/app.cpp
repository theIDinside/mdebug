/** LICENSE TEMPLATE */
#include "app.h"

// mdb
#include <tracer.h>
#include <utils/debugger_thread.h>
#include <utils/logger.h>
#include <utils/thread_pool.h>

// std
#include <string_view>

namespace mdb {

static void
InitializeCommandsInRegistry(cfg::CommandLineRegistry &parser)
{
  parser.AddLambdaCommand("-h", "--help", "Show help", [&p = parser](mdb::cfg::ArgIterator &reader) {
    auto maybeNextValue = reader.GetNext();
    if (!maybeNextValue) {
      p.PrintHelp();
      exit(0);
    }

    std::println("Usage for:");
    std::vector<std::string_view> unknown{};
    for (auto v = maybeNextValue; v; v = reader.GetNext()) {
      bool handled = false;
      for (const auto &opt : p.GetOptions()) {
        if (*v == opt->mLongName || *v == opt->mShortName) {
          auto [left, right] = p.GetTerminalSize();
          UsagePrintFormatting<mdb::cfg::OptionMetadata> arg{ *opt, left, right };
          std::println("{}", arg);
          handled = true;
        }
      }
      if (!handled) {
        unknown.push_back(*v);
      }
    }
    if (!unknown.empty()) {
      std::println("Unrecognized input ({}):", unknown.size());
      std::println("{}", JoinFormatIterator{ unknown, "\n" });
    }
    exit(0);
  });
}

void
Start(int argc, const char **argv, [[maybe_unused]] const char **envp)
{
  static mdb::cfg::CommandLineRegistry parser{};

  InitializeCommandsInRegistry(parser);
  auto configurationOptions = mdb::cfg::InitializationConfiguration::ConfigureWithParser(parser);

  mdb::cfg::CommandLineResult result = parser.Parse(argc, argv);
  if (!result.mErrors.empty()) {
    parser.PrintHelp();
    std::print("\n");
    for (const auto &err : result.mErrors) {
      std::println("Parse error: {}. inputs={{ {} }}", err.mError, JoinFormatIterator{ err.mInputs });
    }
    exit(-1);
  }

  // Sets main thread id. It's static so subsequent calls from other threads should be fine.
  GetProcessId();
  EventSystem *eventSystem = EventSystem::Initialize();
  logging::Logger::ConfigureLogging(*configurationOptions);

  // Thread pool size has a default value. If it's been parsed by the CLI parser, it will return that value
  // It's safe to access all configuration values (that has defaults) after parse, since if there were parse
  // errors, mdb exits. mdb does not allow fallback from errors during cli args parse, only defaults for not-seen
  // ones.
  ThreadPool::GetGlobalPool()->Init(configurationOptions->mThreadPoolSize);

  signal(SIGTERM, [](int sig) {
    if (auto logger = logging::ProfilingLogger::Instance(); logger && sig == SIGTERM) {
      logger->Shutdown();
    }
    EventSystem::Get().PushInternalEvent(TerminateDebugging{});
    ui::dap::AtExit();
  });

  DBGLOG(core, "MDB CLI Arguments");
  for (const auto arg : std::span{ argv, argv + argc }.subspan(1)) {
    DBGLOG(core, "{}", arg);
  }

  Tracer::Create();

  // mdb::logging::ProfilingLogger::ConfigureProfiling(config.LogDirectory());
  logging::ProfilingLogger::ConfigureProfiling(fs::current_path());

  // spawn the UI thread that runs our UI loop
  bool uiThreadSetup = false;

  ui::dap::DebugAdapterClient *userInterface = std::visit(
    [&](const auto &setting) -> ui::dap::DebugAdapterClient * {
      using T = std::decay_t<decltype(setting)>;
      if constexpr (std::is_same_v<cfg::UseStdio, T>) {
        return ui::dap::DebugAdapterClient::CreateStandardIOConnection();
      } else if constexpr (std::is_same_v<cfg::UnixSocket, T>) {
        return ui::dap::DebugAdapterClient::CreateSocketConnection(
          setting.mPath.data(), configurationOptions->mWaitForConnectionTimeout);
      } else {
        static_assert(always_false<T>, "Unhandled debug adapter interface type.");
      }
    },
    configurationOptions->mDebugAdapterInterface);

  if (!userInterface) {
    std::println("Failed to instantiate user interface.");
    exit(-1);
  }

  auto debugAdapterThread =
    DebuggerThread::SpawnDebuggerThread("IO-Thread", [&uiThreadSetup, userInterface](std::stop_token &token) {
      ui::dap::DapEventSystem dap{ userInterface };
      Tracer::Get().SetUI(&dap);
      uiThreadSetup = true;
      dap.StartIOPolling(token);
    });

  while (!uiThreadSetup) {
    std::this_thread::sleep_for(std::chrono::milliseconds{ 1 });
  }
  DBGLOG(core, "UI thread initialized and configured.");

  Tracer::InitializeDapSerializers();
  Tracer::InitInterpreterAndStartDebugger(std::move(debugAdapterThread), eventSystem);
  Tracer::Get().Shutdown();

  DBGLOG(core, "Exited...");
}
} // namespace mdb