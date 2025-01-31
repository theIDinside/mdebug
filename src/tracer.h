/** LICENSE TEMPLATE */
#pragma once

#include "bp.h"
#include "common.h"
#include "event_queue.h"
#include "events/event.h"
#include "interface/attach_args.h"
#include "interface/console_command.h"
#include "interface/dap/interface.h"
#include "interface/tracee_command/gdb_remote_commander.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include <mdb_config.h>
#include <mdbsys/ptrace.h>
#include <memory_resource>
#include <notify_pipe.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unordered_map>
#include <utils/immutable.h>

class JSContext;

namespace mdb::js {
class AppScriptingInstance;
}
namespace mdb {

class ObjectFile;
class SymbolFile;
class TraceeController;
class WaitStatusReaderThread;
struct LWP;
struct TaskInfo;

using Pid = pid_t;
using Tid = pid_t;
using BreakpointSpecId = u32;
using VarRefKey = u32;
} // namespace mdb
namespace mdb::gdb {
class RemoteConnection;
struct RemoteSettings;
} // namespace mdb::gdb

namespace mdb::ui::dap {
class DAP;
struct Event;
struct Scope;
} // namespace mdb::ui::dap

namespace mdb::cmd {
class Command;
};

namespace mdb::ui {
struct UICommand;
}

namespace mdb {

enum class ContextType : u8
{
  Frame,
  Scope,
  Variable,
  Global,
};

struct VariableContext
{
  TraceeController *tc{nullptr};
  TaskInfo *t{nullptr};
  SymbolFile *symbol_file{nullptr};
  u32 frame_id{0};
  u16 id{0};
  ContextType type{ContextType::Global};

  static VariableContext
  subcontext(u32 newId, const VariableContext &ctx) noexcept
  {
    return VariableContext{
      ctx.tc, ctx.t, ctx.symbol_file, ctx.frame_id, static_cast<u16>(newId), ContextType::Variable};
  }

  bool valid_context() const noexcept;
  std::optional<std::array<ui::dap::Scope, 3>> scopes_reference(VarRefKey frameKey) const noexcept;
  sym::Frame *get_frame(VarRefKey ref) noexcept;
  SharedPtr<sym::Value> get_maybe_value() const noexcept;
};

enum class TracerProcess
{
  Running,
  RequestedShutdown,
  Shutdown
};

/** -- A Singleton instance --. There can only be one. (well, there should only be one.)*/
class Tracer
{
  static TracerProcess sApplicationState;
  static termios sOriginalTty;
  static winsize sTerminalWindowSize;
  static Tracer *sTracerInstance;
  static mdb::js::AppScriptingInstance *sScriptRuntime;
  // same as sScriptRuntime::mContext. But it's used so often that having direct access to it, is sensible.
  static JSContext *sApplicationJsContext;
  static bool sUsePTraceMe;
#ifdef MDB_DEBUG
  u64 mDebuggerEvents;

public:
  constexpr bool
  SeenNewEvents(u64 previousEvent) noexcept
  {
    return mDebuggerEvents > previousEvent;
  }

  constexpr u64 &
  DebuggerEventCount() noexcept
  {
    return mDebuggerEvents;
  }

private:
#endif
public:
  friend struct ui::UICommand;
  Tracer(sys::DebuggerConfiguration) noexcept;

  static Tracer *Create(sys::DebuggerConfiguration) noexcept;

  static bool IsRunning() noexcept;
  static bool UsingTraceMe() noexcept;
  static Tracer &Get() noexcept;

  void TerminateSession() noexcept;
  void AddLaunchedTarget(const tc::InterfaceConfig &config, TargetSession session) noexcept;
  void LoadAndProcessObjectFile(pid_t target, const Path &objfile_path) noexcept;
  TraceeController *get_controller(pid_t pid) noexcept;
  TraceeController *GetProcessContainingTid(Tid tid) noexcept;
  // TODO(simon): This should be removed. When multiprocess becomes a thing _all_ supervisor access must happen via
  // a process id or some other handle/id. this is just for convenience when developing the product, really.
  void config_done(ui::dap::DebugAdapterClient *client) noexcept;
  TraceEvent *ConvertWaitEvent(TaskWaitResult wait_res) noexcept;
  Ref<TaskInfo> TakeUninitializedTask(Tid tid) noexcept;
  void handle_command(ui::UICommand *cmd) noexcept;
  void HandleTracerEvent(TraceEvent *evt) noexcept;
  void HandleInternalEvent(InternalEvent evt) noexcept;
  void HandleInitEvent(TraceEvent *evt) noexcept;
  void SetupConsoleCommands() noexcept;
  std::pmr::string EvaluateDebugConsoleExpression(const std::string &expression, bool escapeOutput,
                                                  std::pmr::memory_resource *allocator) noexcept;

  void SetUI(ui::dap::DAP *dap) noexcept;
  void KillUI() noexcept;

  TraceeController *AddNewSupervisor(std::unique_ptr<TraceeController> tc) noexcept;
  void Launch(ui::dap::DebugAdapterClient *client, bool stopAtEntry, const Path &program,
              std::span<const std::string> prog_args,
              std::optional<BreakpointBehavior> breakpointBehavior) noexcept;
  bool Attach(const AttachArgs &args) noexcept;
  bool RemoteAttachInit(tc::GdbRemoteCommander &tc) noexcept;

  std::shared_ptr<SymbolFile> LookupSymbolfile(const std::filesystem::path &path) noexcept;

  std::shared_ptr<gdb::RemoteConnection>
  ConnectToRemoteGdb(const tc::GdbRemoteCfg &config, const std::optional<gdb::RemoteSettings> &settings) noexcept;

  u32 GenerateNewBreakpointId() noexcept;
  VarRefKey NewVariablesReference() noexcept;
  VariableContext GetVariableContext(VarRefKey varRefKey) noexcept;
  VarRefKey NewVariablesReferenceContext(TraceeController &tc, TaskInfo &t, u32 frameId,
                                         SymbolFile *file) noexcept;
  void SetVariableContext(VariableContext ctx) noexcept;
  u32 CloneFromVariableContext(const VariableContext &ctx) noexcept;
  void DestroyVariablesReference(VarRefKey key) noexcept;

  std::unordered_map<Tid, Ref<TaskInfo>> &UnInitializedTasks() noexcept;
  void RegisterTracedTask(Ref<TaskInfo> newTask) noexcept;
  Ref<TaskInfo> GetTask(Tid tid) noexcept;
  std::vector<TraceeController *> GetAllProcesses() const noexcept;
  ui::dap::DAP *GetDap() const noexcept;

  static mdb::js::AppScriptingInstance &GetScriptingInstance() noexcept;
  static JSContext *GetJsContext() noexcept;
  static void InitInterpreterAndStartDebugger(EventSystem *eventSystem) noexcept;

private:
  static void MainLoop(EventSystem *eventSystem, mdb::js::AppScriptingInstance *interpreterInstance) noexcept;

  std::vector<std::unique_ptr<TraceeController>> mTracedProcesses;
  ui::dap::DAP *mDAP;
  std::unique_ptr<WaitStatusReaderThread> mWaiterThread;
  u32 mBreakpointID{0};
  VarRefKey mVariablesReferenceCounter{0};
  std::unordered_map<VarRefKey, VariableContext> mVariablesReferenceContext{};
  bool already_launched;
  sys::DebuggerConfiguration config;

  // Apparently, due to the lovely way of the universe, if a thread clones or forks
  // we may actually see the wait status of the clone child before we get to see the wait status of the
  // thread making the clone system call. I guess, this could be tracked, if every single resume operation stopped
  // on system call boundaries (and therefore checked "ARE WE DOING A CLONE? THAT IS A SPECIAL CASE ONE" for
  // instance). For now, we will solve this problem by having an "unitialized" thread; these are the ones that show
  // up before their wait status of their clone parent has been seen. This should work.
  std::unordered_map<Tid, Ref<TaskInfo>> mUnInitializedThreads{};
  std::unordered_map<Tid, Ref<TaskInfo>> mDebugSessionTasks;
  std::unordered_map<Tid, ui::dap::DebugAdapterClient *> mDebugAdapterConnections;
  std::vector<std::unique_ptr<TraceeController>> mExitedProcesses;
  ConsoleCommandInterpreter *mConsoleCommandInterpreter;
};
} // namespace mdb