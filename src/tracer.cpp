/** LICENSE TEMPLATE */
#include "tracer.h"

// mdb
#include <bp.h>
#include <common/macros.h>
#include <common/typedefs.h>
#include <configuration/command_line.h>
#include <event_queue.h>
#include <interface/attach_args.h>
#include <interface/console_command.h>
#include <interface/dap/dap_defs.h>
#include <interface/dap/events.h>
#include <interface/dap/interface.h>
#include <interface/pty.h>
#include <interface/tracee_command/ptrace/ptrace_session.h>
#include <interface/tracee_command/rr/rr_session.h>
#include <interface/tracee_command/supervisor_state.h>
#include <lib/arena_allocator.h>
#include <lib/lockguard.h>
#include <lib/spinlock.h>
#include <lib/stack.h>
#include <mdbjs/mdbjs.h>
#include <session_task_map.h>
#include <symbolication/dwarf_frameunwinder.h>
#include <symbolication/objfile.h>
#include <symbolication/value.h>
#include <symbolication/value_visualizer.h>
#include <sys/ptrace.h>
#include <task.h>
#include <task_scheduling.h>
#include <utils/expected.h>
#include <utils/format_utils.h>
#include <utils/logger.h>
#include <utils/scope_defer.h>
#include <utils/scoped_fd.h>
#include <utils/thread_pool.h>
#include <utils/util.h>

// dependency
#include <mdbjs/include-quickjs.h>

// stdlib
#include <algorithm>
#include <utility>

// system
#include <dirent.h>
#include <fcntl.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <unistd.h>

namespace mdb {

Tracer::Tracer() noexcept : mDebugSessionTasks(std::make_unique<SessionTaskMap>())
{
  MDB_ASSERT(Tracer::sTracerInstance == nullptr,
    "Multiple instantiations of the Debugger - Design Failure, this = 0x{:x}, older instance = 0x{:x}",
    (uintptr_t)this,
    (uintptr_t)sTracerInstance);
  mConsoleCommandInterpreter = new ConsoleCommandInterpreter{};
}

// static
Tracer *
Tracer::Create() noexcept
{
  sTracerInstance = new Tracer{};
  return sTracerInstance;
}

/* static */
bool
Tracer::IsRunning() noexcept
{
  return sApplicationState == TracerProcess::Running;
}

/* static */
bool
Tracer::UsingTraceMe() noexcept
{
  return sUsePTraceMe;
}

// static
Tracer &
Tracer::Get() noexcept
{
  return *sTracerInstance;
}

/* static */
ui::dap::DebugAdapterManager &
Tracer::GetDebugAdapterManager() noexcept
{
  return *Get().mDebugAdapterManager;
}

/* static */
void
Tracer::SetDebugAdapterManager(ui::dap::DebugAdapterManager *dap) noexcept
{
  Get().mDebugAdapterManager = dap;
}

void
Tracer::OnDisconnectOrExit(tc::SupervisorState *supervisor) noexcept
{
  auto it = FindSupervisor(supervisor);
  if (it == std::end(mTracedProcesses)) {
    return;
  }
  mDetachedProcesses.push_back(std::move(*it));
  mTracedProcesses.erase(it);

  if (mTracedProcesses.empty()) {
    EventSystem::Get().PushInternalEvent(TerminateDebugging{});
  }
}

tc::SupervisorState *
Tracer::GetProcessContainingTid(Tid tid) noexcept
{
  for (auto &t : mTracedProcesses) {
    if (t->GetTaskByTid(tid)) {
      return t.get();
    }
  }
  return nullptr;
}

tc::SupervisorState *
Tracer::GetController(pid_t pid) noexcept
{
  auto it = std::ranges::find_if(mTracedProcesses, [&pid](auto &t) { return t->TaskLeaderTid() == pid; });
  MDB_ASSERT(it != std::end(mTracedProcesses), "Could not find target {} pid", pid);

  return it->get();
}

void
Tracer::ExecuteCommand(RefPtr<ui::UICommand> cmd) noexcept
{
  cmd->Execute();
  cmd->mDebugAdapterManager->FlushEvents();
}

std::optional<TaskControl<tc::ptrace::Session>>
Tracer::GetPtraceProcess(pid_t tidOrPid) noexcept
{
  for (const auto &proc : mTracedProcesses) {
    auto task = proc->GetTaskByTid(tidOrPid);
    if (task) {
      return std::make_optional<TaskControl<tc::ptrace::Session>>(
        *static_cast<tc::ptrace::Session *>(proc.get()), *task);
    }
  }
  return {};
}

void
Tracer::HandlePtraceEvent(PtraceEvent event) noexcept
{
  std::optional<TaskControl<tc::ptrace::Session>> taskAndControl = GetPtraceProcess(event.mPid);
  if (!taskAndControl.has_value()) {
    tc::ptrace::Session::QueueUnhandledPtraceEvent(event);
  } else {
    auto &[control, task] = *taskAndControl;
    control.HandleEvent(task, event);
  }
}

tc::replay::Session *
Tracer::GetReplayProcess(pid_t tidOrPid) noexcept
{
  for (const auto &proc : mTracedProcesses) {
    auto task = proc->GetTaskByTid(tidOrPid);
    if (task) {
      return static_cast<tc::replay::Session *>(proc.get());
    }
  }
  return nullptr;
}

void
Tracer::HandleReplayStopEvent(ReplayEvent evt) noexcept
{
  tc::replay::Session *session = GetReplayProcess(evt.mTaskInfo.mTaskLeader);
  session->HandleEvent(evt);
}

void
Tracer::HandleGdbEvent(GdbServerEvent *evt) noexcept
{
  TODO("Tracer::HandleGdbEvent(GdbServerEvent *evt) noexcept");
}

void
Tracer::HandleInternalEvent(const InternalEvent &evt) noexcept
{
  switch (evt.mType) {
  case InternalEventDiscriminant::InvalidateSupervisor: {
    auto sv = evt.uInvalidateSupervisor.mSupervisor;
    auto it = std::find_if(
      mTracedProcesses.begin(), mTracedProcesses.end(), [sv](const auto &t) { return t.get() == sv; });
    if (it != std::end(mTracedProcesses)) {
      sv->OnTearDown();
      std::unique_ptr<tc::SupervisorState> swap = std::move(*it);
      mTracedProcesses.erase(it);
      mDetachedProcesses.push_back(std::move(swap));
    }

    if (mTracedProcesses.empty()) {
      sApplicationState = TracerProcess::RequestedShutdown;
    }
  } break;
  case mdb::InternalEventDiscriminant::TerminateDebugging: {
    sApplicationState = TracerProcess::RequestedShutdown;
    break;
  }
  case mdb::InternalEventDiscriminant::InitializedWaitSystem: {
    break;
  }
  default:
    PANIC("Unhandled internal event");
  }
}

#define ReturnEvalExprError(errorCondition, msg, ...)                                                             \
  if ((errorCondition)) {                                                                                         \
    std::format_to(std::back_inserter(evalResult), msg __VA_OPT__(, ) __VA_ARGS__);                               \
    return ConsoleCommandResult{ false, evalResult };                                                             \
  }

#define OK_RESULT(res)                                                                                            \
  ConsoleCommandResult { true, std::move(res) }

std::pmr::string *
Tracer::EvaluateDebugConsoleExpression(const std::string &expression, Allocator *allocator) noexcept
{
  auto res = mConsoleCommandInterpreter->Interpret(expression, allocator);
  return res.mContents;
}

void
Tracer::SetUI(ui::dap::DapEventSystem *dap) noexcept
{
  this->mDAP = dap;
}

void
Tracer::KillUI() noexcept
{
  mDAP->CleanUp();
}

static bool
PtraceAttach(ui::dap::DebugAdapterManager *client, SessionId sessionId, const PtraceAttachArgs &args) noexcept
{
  auto supervisor = Tracer::Get().GetController(args.pid);
  if (!supervisor) {
    TODO("Implement attaching to running process that was not previously ptraced.");
  }
  // The DAP request was made for a supervisor that was not of the right type.
  if (supervisor->mSupervisorType != tc::SupervisorType::Native) {
    return false;
  }

  auto session = client->GetSession(sessionId);
  supervisor->AttachSession(*session);

  return true;
}

static bool
RRAttach(ui::dap::DebugAdapterManager *client, SessionId sessionId, const RRAttachArgs &args) noexcept
{
  auto supervisor = Tracer::Get().GetController(args.pid);
  MDB_ASSERT(supervisor, "No supervisor with {}", args.pid);
  // The DAP request was made for a supervisor that was not of the right type.
  if (supervisor->mSupervisorType != tc::SupervisorType::RR) {
    return false;
  }

  auto session = client->GetSession(sessionId);
  supervisor->AttachSession(*session);

  return true;
}

bool
Tracer::SessionAttach(ui::dap::DebugAdapterManager *client, SessionId sessionId, const AttachArgs &args) noexcept
{
  using MatchResult = Pid;

  return std::visit(
    Match{ [&](const PtraceAttachArgs &args) -> MatchResult { return PtraceAttach(client, sessionId, args); },
      [&](const RRAttachArgs &args) -> MatchResult { return RRAttach(client, sessionId, args); },
      [&](const GdbRemoteAttachArgs &gdb) -> MatchResult {
        TODO("Implement attach for gdbserver sessions");
        /*
        DBGLOG(core, "Initializing remote protocol interface...");
        // Since we may connect to a remote that is not connected to nuthin,
        // we need an extra step here (via the RemoteSessionConfiguirator), before
        // we can actually be served a TraceeInterface of GdbRemoteCommander type (or actually
        // 0..N of them) Why? Because when we ptrace(someprocess), we know we are attaching to
        // 1 process, that's it. But the remote target might actually be attached to many, and
        // we want our design to be consistent (1 commander / process. Otherwise we turn into
        // gdb hell hole.)
        auto remote_init = tc::RemoteSessionConfigurator{ Tracer::Get().ConnectToRemoteGdb(
          { .host = std::string{ gdb.host }, .port = gdb.port }, {}) };

        std::vector<tc::RemoteProcess> res;

        switch (gdb.type) {
        case RemoteType::RR: {
          auto result = remote_init.configure_rr_session();
          if (result.is_expected()) {
            res = std::move(result.take_value());
          } else {
            PANIC("Failed to configure session");
          }
        } break;
        case RemoteType::GDB: {
          auto result = remote_init.configure_session();
          if (result.is_expected()) {
            res = std::move(result.take_value());
          } else {
            PANIC("Failed to configure session");
          }
        } break;
        }

        auto it = res.begin();
        const auto firstAttachedId = it->tc->TaskLeaderTid();

        const auto hookupDapWithRemote =
          [&](auto &&newSupervisor, ui::dap::DebugAdapterClient *client, bool newProc) {
            mTracedProcesses.push_back(std::move(newSupervisor));
            auto *supervisor = mTracedProcesses.back().get();
            auto &ti = supervisor->GetInterface();
            ti.OnExec();
            for (const auto &t : it->threads) {
              supervisor->CreateNewTask(t.tid, false);
            }
            for (auto &entry : supervisor->GetThreads()) {
              entry.mTask->SetAtTraceEventStop();
            };

            if (newProc) {
              client->PostDapEvent(new ui::dap::Process{ 0, supervisor->TaskLeaderTid(), "process",
        false });
            }
          };

        auto mainConnection = mDAP->Get();

        (void)Tracer::Get().AddTracedSupervisor(sessionId, [&](tc::SupervisorState *supervisor) {
          supervisor->InitializeInterface(TargetSession::Attached, std::move(it->tc),
        InterfaceType::GdbRemote); auto &ti = supervisor->GetInterface(); ti.OnExec(); for (const
        auto &t : it->threads) { if (!supervisor->HasTask(t.tid)) {
              supervisor->CreateNewTask(t.tid, false);
            }
          }
          for (auto &entry : supervisor->GetThreads()) {
            entry.mTask->SetAtTraceEventStop();
          };
        });

        mainConnection->SetDebugAdapterSessionType(
          (gdb.type == RemoteType::GDB) ? ui::dap::DapClientSession::Attach :
        ui::dap::DapClientSession::RR);
        ++it;
        for (; it != std::end(res); ++it) {

          hookupDapWithRemote(tc::SupervisorState::create(Tracer::Get().NewSupervisorId(),
                                TargetSession::Attached,
                                std::move(it->tc),
                                InterfaceType::GdbRemote),
            mainConnection,
            true);
        }
        return firstAttachedId;
        */
        return 0;
      } },
    args);
}

/* static */
tc::SupervisorState *
Tracer::AddSupervisor(UniquePtr<tc::SupervisorState> supervisor) noexcept
{
  static SessionId latestSessionId = 0;
  MDB_ASSERT(supervisor->GetSessionId() > latestSessionId || supervisor->GetSessionId() == -1,
    "Preparing a new session with a previously used ID is not supported.");
  latestSessionId = supervisor->GetSessionId();
  return Get().mTracedProcesses.emplace_back(std::move(supervisor)).get();
}

/* static */
SessionTaskMap &
Tracer::GetSessionTaskMap() noexcept
{
  return *Tracer::Get().mDebugSessionTasks;
}

std::shared_ptr<SymbolFile>
Tracer::LookupSymbolfile(const std::filesystem::path &path) noexcept
{
  for (const auto &t : mTracedProcesses) {
    if (std::shared_ptr<SymbolFile> sym = t->LookupSymbolFile(path); sym) {
      return sym;
    }
  }
  return nullptr;
}

// std::shared_ptr<gdb::RemoteConnection>
// Tracer::ConnectToRemoteGdb(
//   const tc::GdbRemoteCfg &config, const std::optional<gdb::RemoteSettings> &settings) noexcept
// {
//   for (auto &t : mTracedProcesses) {
//     if (auto conn = t->GetInterface().RemoteConnection(); conn && conn->IsConnectedTo(config.host, config.port))
//     {
//       return conn;
//     }
//   }
//   auto connection = gdb::RemoteConnection::Connect(config.host, config.port, settings);
//   if (connection.is_error()) {
//     DBGLOG(core, "failed to connect to {}:{}", config.host, config.port);
//     PANIC("Exiting after hard failure");
//   }
//   return connection.take_value();
// }

/*static */ u32
Tracer::GenerateNewBreakpointId() noexcept
{
  Get().mBreakpointID++;
  return Get().mBreakpointID;
}

VariableReferenceId
Tracer::NewVariablesReference() noexcept
{
  return ++mVariablesReferenceCounter;
}

VariableReferenceId
Tracer::GetCurrentVariableReferenceBoundary() const noexcept
{
  return mVariablesReferenceCounter;
}

sym::VarContext
Tracer::GetVariableContext(VariableReferenceId varRefKey) noexcept
{
  if (mVariablesReferenceContext.contains(varRefKey)) {
    return mVariablesReferenceContext[varRefKey];
  }
  return nullptr;
}

void
Tracer::DestroyVariablesReference(VariableReferenceId key) noexcept
{
  mVariablesReferenceContext.erase(key);
}

/* static */
Ref<TaskInfo>
Tracer::GetThreadByTidOrDebugId(Tid tid) noexcept
{
  auto t = Tracer::Get().mDebugSessionTasks->Get(tid);
  if (t) {
    return RefPtr{ t };
  }
  return Tracer::Get().GetTaskBySessionId(static_cast<u32>(tid));
}

Ref<TaskInfo>
Tracer::GetTaskBySessionId(u32 sessionId) noexcept
{
  auto task = mDebugSessionTasks->GetBySessionId(sessionId);
  if (!task) {
    return nullptr;
  }
  return RefPtr{ task };
}

tc::SupervisorState *
Tracer::GetSupervisorBySessionId(SessionId sessionId) noexcept
{
  for (auto &t : mTracedProcesses) {
    if (t->GetSessionId() == sessionId) {
      return t.get();
    }
  }
  return nullptr;
}

std::vector<tc::SupervisorState *>
Tracer::GetAllProcesses() const noexcept
{
  std::vector<tc::SupervisorState *> result;
  result.reserve(mTracedProcesses.size() + mDetachedProcesses.size());
  for (auto &p : mTracedProcesses) {
    result.push_back(p.get());
  }

  for (auto &p : mDetachedProcesses) {
    result.push_back(p.get());
  }

  return result;
}

ui::dap::DapEventSystem *
Tracer::GetDap() const noexcept
{
  return mDAP;
}

void
Tracer::SetVariableContext(std::shared_ptr<VariableContext> ctx) noexcept
{
  auto id = ctx->mId;
  ctx->mTask->AddReference(id);
  mVariablesReferenceContext[id] = std::move(ctx);
}

sym::VarContext
Tracer::CloneFromVariableContext(const VariableContext &ctx) noexcept
{
  if (ctx.mTask->VariableReferenceIsStale(ctx.mId)) {
    // Don't register new context with mVariablesReferenceContext, because the cloned context is cloned from a
    // stale context
    return VariableContext::CloneFrom(ctx.mId - 1, ctx);
  }
  const auto key = NewVariablesReference();

  auto context = VariableContext::CloneFrom(key, ctx);
  mVariablesReferenceContext.emplace(key, context);
  return context;
}

/* static */
void
Tracer::InitializeDapSerializers() noexcept
{
  auto &tracer = Get();
  tracer.mInvalidValueDapSerializer = new sym::InvalidValueVisualizer{};
  tracer.mArrayValueDapSerializer = new sym::ArrayVisualizer{};
  tracer.mPrimitiveValueDapSerializer = new sym::PrimitiveVisualizer{};
  tracer.mDefaultStructDapSerializer = new sym::DefaultStructVisualizer{};
  tracer.mCStringDapSerializer = new sym::CStringVisualizer{};

  tracer.mResolveReference = new sym::ResolveReference{};
  tracer.mResolveCString = new sym::ResolveCString{};
  tracer.mResolveArray = new sym::ResolveArray{};

  DBGLOG(core, "Debug Adapter serializers initialized.");
}

void
Tracer::Shutdown() noexcept
{
  mdb::ThreadPool::ShutdownGlobalPool();
  KillUI();
  mDebugAdapterThread->RequestStop();
#ifdef MDB_PROFILE_LOGGER
  ShutdownProfiling();
#endif
}

void
Tracer::ShutdownProfiling() noexcept
{
  logging::ProfilingLogger::Instance()->Shutdown();
}

u32
Tracer::NewSupervisorId() noexcept
{
  return mSessionProcessId++;
}

/* static */
void
Tracer::InitInterpreterAndStartDebugger(
  std::unique_ptr<DebuggerThread> debugAdapterThread, EventSystem *eventSystem) noexcept
{
  Get().mDebugAdapterThread = std::move(debugAdapterThread);

  auto interpreter = js::Scripting::Create();
  MainLoop(eventSystem, interpreter);
  interpreter->Shutdown();
}

void
Tracer::MainLoop(EventSystem *eventSystem, mdb::js::Scripting *scriptRuntime) noexcept
{
  auto &dbgInstance = Get();
  dbgInstance.sScriptRuntime = scriptRuntime;

  std::vector<ApplicationEvent> readInEvents{};
  readInEvents.reserve(128);

  while (dbgInstance.IsRunning()) {
    if (eventSystem->PollBlocking(readInEvents)) {
      for (auto &&evt : readInEvents) {
        switch (evt.mEventType) {
        case ApplicationEventType::Ptrace: {
          dbgInstance.HandlePtraceEvent(evt.uPtrace);
        } break;
        case ApplicationEventType::GdbServer: {
          dbgInstance.HandleGdbEvent(evt.uGdbServer);
        } break;
        case ApplicationEventType::RR: {
          dbgInstance.HandleReplayStopEvent(evt.uReplayStop);
        } break;
        case ApplicationEventType::Command: {
          dbgInstance.ExecuteCommand(evt.uCommand.Materialize());
        } break;
        case ApplicationEventType::Internal: {
          dbgInstance.HandleInternalEvent(evt.uInternalEvent);
        } break;
        }
      }
      readInEvents.clear();
    }
  }
}
} // namespace mdb