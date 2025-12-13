/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <bp.h>
#include <common.h>
#include <configuration/command_line.h>
#include <event_queue.h>
#include <events/event.h>
#include <interface/attach_args.h>
#include <interface/console_command.h>
#include <interface/dap/interface.h>
#include <lib/stack.h>
#include <mdb_config.h>
#include <notify_pipe.h>
#include <symbolication/value.h>
#include <symbolication/value_visualizer.h>
#include <symbolication/variable_reference.h>
#include <utils/debugger_thread.h>
#include <utils/immutable.h>

// stdlib
#include <memory>
#include <unordered_map>

// system
#include <sys/ioctl.h>
#include <termios.h>

struct JSContext;

namespace mdb::js {
class Scripting;
}
namespace mdb {

class ObjectFile;
class SymbolFile;
class SessionTaskMap;

struct LWP;
class TaskInfo;

using Pid = pid_t;
using Tid = pid_t;
using BreakpointSpecId = u32;

} // namespace mdb

namespace mdb::tc {

class SupervisorState;

namespace ptrace {
class Session;
}

namespace replay {
class Session;
}

} // namespace mdb::tc

namespace mdb::gdb {
class RemoteConnection;
struct RemoteSettings;
} // namespace mdb::gdb

namespace mdb::ui::dap {
class DapEventSystem;
struct Event;
struct Scope;
} // namespace mdb::ui::dap

namespace mdb::cmd {
class Command;
};

namespace mdb::sym {
// The base class serializer
class DebugAdapterSerializer;
class InvalidValueVisualizer;
class ArrayVisualizer;
class PrimitiveVisualizer;
class DefaultStructVisualizer;
class CStringVisualizer;
} // namespace mdb::sym

namespace mdb::ui {
struct UICommand;
}

namespace mdb {

struct InternalEvent;

enum class TracerProcess : u8
{
  Running,
  RequestedShutdown,
  Shutdown
};

struct UnInitializedSupervisor
{
  SessionId mSessionId;
  std::unique_ptr<tc::SupervisorState> mSupervisor;
};

template <typename ControlType> struct TaskControl
{
  ControlType &mControl;
  TaskInfo &mTask;
};

/** -- A Singleton instance --. There can only be one. (well, there should only be one.)*/
class Tracer
{

  static TracerProcess sApplicationState;
  static termios sOriginalTty;
  static winsize sTerminalWindowSize;
  static Tracer *sTracerInstance;
  static mdb::js::Scripting *sScriptRuntime;
  // same as sScriptRuntime::mContext. But it's used so often that having direct access to it, is sensible.
  static JSContext *sApplicationJsContext;
  ui::dap::DebugAdapterManager *mDebugAdapterManager;
  static bool sUsePTraceMe;
  static int sLastTraceEventTime;

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

#ifdef MDB_DEBUG
  constexpr void
  IncrementDebuggerTime() noexcept
  {
    mDebuggerEvents++;
  }
#endif

private:
#endif
public:
  friend struct ui::UICommand;
  Tracer() noexcept;

  static Tracer *Create() noexcept;

  static bool IsRunning() noexcept;
  static bool UsingTraceMe() noexcept;
  static Tracer &Get() noexcept;
  static ui::dap::DebugAdapterManager &GetDebugAdapterManager() noexcept;
  static void SetDebugAdapterManager(ui::dap::DebugAdapterManager *dap) noexcept;

  void OnDisconnectOrExit(tc::SupervisorState *supervisor) noexcept;
  tc::SupervisorState *GetController(pid_t pid) noexcept;
  tc::SupervisorState *GetProcessContainingTid(Tid tid) noexcept;

  void ExecuteCommand(RefPtr<ui::UICommand> cmd) noexcept;

  // The main event handlers for the different session types.
  std::optional<TaskControl<tc::ptrace::Session>> GetPtraceProcess(pid_t tidOrPid) noexcept;
  void HandlePtraceEvent(PtraceEvent event) noexcept;

  tc::replay::Session *GetReplayProcess(pid_t tidOrPid) noexcept;
  void HandleReplayStopEvent(ReplayEvent evt) noexcept;

  void HandleGdbEvent(GdbServerEvent *evt) noexcept;
  void HandleInternalEvent(const InternalEvent &evt) noexcept;
  std::pmr::string *EvaluateDebugConsoleExpression(const std::string &expression, Allocator *allocator) noexcept;

  void SetUI(ui::dap::DapEventSystem *dap) noexcept;
  void KillUI() noexcept;

  // Returns the PID we've attached to; if we've attached to a remote target, there's a chance
  // that we may have in fact really attached to multiple processes. In this case, this is just the "first" process
  // id that we return - the remainder of the processes will get auto attached (via attach requests using the
  // "auto" type) which essentially is just a thin wrapper around attach, to make DAP create new sessions for these
  // processes. In the future, when we've written a new Callstack UI, we can remove all this nonsense, because
  // then, one session can be responsible for multiple processes. Until then, we're stuck with this 1979 version of
  // a protocol.
  bool SessionAttach(ui::dap::DebugAdapterManager *client, SessionId sessionId, const AttachArgs &args) noexcept;

  std::shared_ptr<SymbolFile> LookupSymbolfile(const std::filesystem::path &path) noexcept;

  // std::shared_ptr<gdb::RemoteConnection> ConnectToRemoteGdb(const tc::GdbRemoteCfg &config, const
  // std::optional<gdb::RemoteSettings> &settings) noexcept;

  static u32 GenerateNewBreakpointId() noexcept;
  VariableReferenceId NewVariablesReference() noexcept;
  VariableReferenceId GetCurrentVariableReferenceBoundary() const noexcept;
  sym::VarContext GetVariableContext(VariableReferenceId varRefKey) noexcept;

  void SetVariableContext(std::shared_ptr<VariableContext> ctx) noexcept;
  sym::VarContext CloneFromVariableContext(const VariableContext &ctx) noexcept;
  void DestroyVariablesReference(VariableReferenceId key) noexcept;

  Ref<TaskInfo> GetTaskBySessionId(u32 sessionId) noexcept;
  static Ref<TaskInfo> GetThreadByTidOrDebugId(Tid tid) noexcept;
  tc::SupervisorState *GetSupervisorBySessionId(SessionId sessionId) noexcept;
  std::vector<tc::SupervisorState *> GetAllProcesses() const noexcept;
  ui::dap::DapEventSystem *GetDap() const noexcept;

  static void InitInterpreterAndStartDebugger(
    std::unique_ptr<DebuggerThread> debugAdapterThread, EventSystem *eventSystem) noexcept;
  static void InitializeDapSerializers() noexcept;

  void Shutdown() noexcept;
  void ShutdownProfiling() noexcept;

  template <typename DapSerializer>
  static DapSerializer *
  GetSerializer() noexcept
  {
    using namespace sym;
    if constexpr (std::is_same_v<DapSerializer, InvalidValueVisualizer>) {
      return Get().mInvalidValueDapSerializer;
    } else if constexpr (std::is_same_v<DapSerializer, ArrayVisualizer>) {
      return Get().mArrayValueDapSerializer;
    } else if constexpr (std::is_same_v<DapSerializer, PrimitiveVisualizer>) {
      return Get().mPrimitiveValueDapSerializer;
    } else if constexpr (std::is_same_v<DapSerializer, DefaultStructVisualizer>) {
      return Get().mDefaultStructDapSerializer;
    } else if constexpr (std::is_same_v<DapSerializer, CStringVisualizer>) {
      return Get().mCStringDapSerializer;
    } else {
      static_assert(always_false<DapSerializer>, "Invalid DAP serializer - write a new one?");
    }
  }

  template <typename ValueResolver>
  static ValueResolver *
  GetResolver() noexcept
  {
    using namespace sym;
    if constexpr (std::is_same_v<ValueResolver, ResolveReference>) {
      return Get().mResolveReference;
    } else if constexpr (std::is_same_v<ValueResolver, ResolveCString>) {
      return Get().mResolveCString;
    } else if constexpr (std::is_same_v<ValueResolver, ResolveArray>) {
      return Get().mResolveArray;
    } else {
      static_assert(always_false<ValueResolver>, "Unsupported type: write a new one?");
    }
  }

  u32 NewSupervisorId() noexcept;

  static tc::SupervisorState *AddSupervisor(UniquePtr<tc::SupervisorState> supervisor) noexcept;
  static SessionTaskMap &GetSessionTaskMap() noexcept;

  auto
  FindSupervisor(tc::SupervisorState *supervisor) noexcept
  {
    return std::find_if(
      mTracedProcesses.begin(), mTracedProcesses.end(), [&](auto &s) { return s.get() == supervisor; });
  }

private:
  static void MainLoop(EventSystem *eventSystem, mdb::js::Scripting *interpreterInstance) noexcept;

  std::unique_ptr<DebuggerThread> mDebugAdapterThread{ nullptr };

  std::vector<UniquePtr<tc::ptrace::Session>> mPtracedProcesses{};

  // Processes under control (and visible to the user/where the user is interested in controlling them)
  std::vector<UniquePtr<tc::SupervisorState>> mTracedProcesses{};
  // Processes that has exited, or has been disconnected (or just ignored)
  std::vector<std::unique_ptr<tc::SupervisorState>> mDetachedProcesses;

  ui::dap::DapEventSystem *mDAP;
  u32 mBreakpointID{ 0 };

  // We do a monotonic increase. Unlike implementations I've previously worked on, and seen (like gdb)
  // We will _never_ reset the variables reference value. It's in fact used to determine "liveness" of variable
  // values. It works like this:
  // Every time a task is stopped (_every_ time), it reads the `current variables reference` value, and sets it as
  // it's new boundary Any values that has been created in this execution context can then compare itself against
  // this "boundary value" and if's above, then we know it's live, if's below, it's at some previous time.
  // Now - just because it's determined that the value is not live, does not mean it's invalid (or even the wrong
  // value!). It just means we can't guarantee it anymore. To guarantee, we need to `refresh` the backing memory
  // (and update the `Value`'s `mVariableReference`)
  VariableReferenceId mVariablesReferenceCounter{ 0 };
  std::unordered_map<VariableReferenceId, sym::VarContext> mVariablesReferenceContext{};
  bool already_launched{ false };

  UniquePtr<SessionTaskMap> mDebugSessionTasks;

  // Sometimes a cloned child's ptrace event shows up, before the ptrace event comes through from the parent
  // in those cases, we stick the child's event into a pending map (from it's Tid -> event), so that it can be
  // handled after we've processed the parent.
  std::unordered_map<Tid, PtraceEvent> mPendingPtraceEvent;
  u32 mSessionThreadId{ 1 };
  u32 mSessionProcessId{ 1 };

  ConsoleCommandInterpreter *mConsoleCommandInterpreter;

  sym::InvalidValueVisualizer *mInvalidValueDapSerializer{ nullptr };
  sym::ArrayVisualizer *mArrayValueDapSerializer{ nullptr };
  sym::PrimitiveVisualizer *mPrimitiveValueDapSerializer{ nullptr };
  sym::DefaultStructVisualizer *mDefaultStructDapSerializer{ nullptr };
  sym::CStringVisualizer *mCStringDapSerializer{ nullptr };

  sym::ResolveReference *mResolveReference{ nullptr };
  sym::ResolveCString *mResolveCString{ nullptr };
  sym::ResolveArray *mResolveArray{ nullptr };
};
} // namespace mdb