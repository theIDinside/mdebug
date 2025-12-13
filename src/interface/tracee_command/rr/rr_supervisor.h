/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common/typedefs.h>
#include <event_queue_types.h>
#include <events/event.h>
#include <utils/immutable.h>

// std
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <thread>

namespace rr {
class ReplayTask;
class Task;
class ReplayTimeline;
struct BreakStatus;
struct ReplayResult;
struct SyscallEvent;
class TraceFrame;
} // namespace rr

#undef FOR_EACH_EVT
#define FOR_EACH_EVT(EVT)                                                                                         \
  EVT(Error, "Error reported by ReplaySession.")                                                                  \
  EVT(Initialized, "Replay session has been initialized")                                                         \
  EVT(ProgressUpdate, "Progress update reported by run-to start")                                                 \
  EVT(TraceStarted, "Replay debug session ready to start.")                                                       \
  EVT(TraceEnded, "Replay ended. No more events to replay (forward)")                                             \
  EVT(Exited, "Replay session exited.")

ENUM_TYPE_METADATA(SupervisorSessionEventType, FOR_EACH_EVT, DEFAULT_ENUM, i8)

namespace mdb::tc::replay {

class Session;

#define RESERVED_BITS 4
#define ENUM_FIELD(ID) (0b1 << RESERVED_BITS) << ID

#define FOR_EACH_SUPERVISOR_EVENT(EVT)                                                                            \
  EVT(RR_EVT_ERROR, 0b0000)                                                                                       \
  EVT(RR_EVT_SUPERVISOR_INITIALIZED, 0b0001)                                                                      \
  EVT(RR_EVT_SUPERVISOR_PROGRESS_UPDATE, 0b0010)                                                                  \
  EVT(RR_EVT_SUPERVISOR_EXITED, 0b0011)                                                                           \
  EVT(RR_EVT_SUPERVISOR_REACHED_EVENT, 0b0100)                                                                    \
  EVT(RR_EVT_SUPERVISOR_TRACE_STARTED, 0b0101)                                                                    \
  EVT(RR_EVT_SUPERVISOR_TRACE_ENDED, 0b0110)                                                                      \
  EVT(RR_EVT_SUPERVISOR_TRACE_NOT_FOUND, 0b0111)

// In the future when we want to support init of different setups.
struct RRInitOptions
{
  std::vector<Pid> mIgnoredProcesses;
};

bool RRInit();

enum class SupervisorEventKind : u8
{
  SupervisorEvent,
  ReplayEvent,
};

struct SessionEvent
{
  SupervisorSessionEventType mType;
  TraceFrameTaskContext mTaskInfo;
};

using SupervisorEvent = std::variant<SessionEvent, ReplayEvent>;

enum class BreakpointRequestType : u8
{
  BREAKPOINT_SW, // software breakpoint
  BREAKPOINT_HW, // hardware breakpoint
};

enum class WatchpointRequestType : u8
{
  WATCHPOINT_EXEC,
  WATCHPOINT_WRITE, // write watchpoint
  WATCHPOINT_RW     // read-write watchpoint
};

struct BreakpointRequest
{
  bool is_hardware;
  uintptr_t address;
};

struct WatchpointRequest
{
  WatchpointRequestType type;
  uintptr_t address;
  size_t size;
};

typedef void (*SupervisorEventCallback)(const SupervisorEvent &evt, void *user_data);

struct StartReplayOptions
{
  const char *trace_dir;
  int64_t goto_event;
};

enum class ResumeType : u8
{
  RR_STEP,
  RR_RESUME
};

enum ReplayDirection : u8
{
  RR_DIR_FORWARD,
  RR_DIR_REVERSE
};

struct ResumeReplay
{
  ResumeType resume_type;
  ReplayDirection direction;
  int steps;
};

struct Process
{
  std::string mExecedFile;
  pid_t mProcessId;
};

// Stop reasons interesting for a debugger front-end. Whether the frontend
// decides to stop to inform the user, is up to the frontend.
enum class StopReason : u8
{
  // Stopped due to internal implementation detail. Gives us leeway to stop for
  // arbitrary new reasons in the future, before actually having to define them.
  // Should theoretically reduce friction. Therefore also spelled out with a
  // huge name.
  SupervisorImplementationDetail,
  SingleStepped,
  Breakpoint,
  Watchpoint,
  Clone,
  Fork, // Technically a CLONE3, really.
  Exec,
  Signal,
};

struct RegisterCacheData
{
  const std::uint8_t *buf;
  size_t cache_size;
};

struct EventCallback
{
  SupervisorEventCallback event_handler{ nullptr };
  void *user_data;

  constexpr void
  operator()(const SupervisorEvent &evt)
  {
    return event_handler(evt, user_data);
  }
};

class ReplaySupervisor
{
  void SpawnSupervisorThread() noexcept;

  // Construction & Initialization
  void SetEventHandler(SupervisorEventCallback eventHandler) noexcept;

  RRInitOptions mInitOptions;
  std::jthread mSupervisorThread;
  rr::ReplayTimeline *mTimeline;
  // Sessions are only ever created once. When replaying backwards across a session creation, we
  // do nothing but notify the UI frontend (via DAP events) that it's "exited" - and once reborn, we just pick it
  // out of this cache and do the hook-up dance with the UI frontend again, via normal DAP processess
  std::vector<Session *> mTimelineSupervisors;

  // Notification of new rr supervisor events
  std::atomic<bool> mKeepRunning{ true };
  std::atomic<bool> mReplayRunning{ false };
  std::atomic<bool> mPendingInterrupt{ false };
  pid_t mLastPendingInterruptFor{ 0 };
  std::optional<ResumeReplay> mRequestedResume{ std::nullopt };
  std::optional<ResumeReplay> mLastRequestedResume{ std::nullopt };
  // If process is not registered with ReplaySupervisor, we don't notify the debugger of events related to it.
  std::vector<Pid> mTracedProcesses{};
  bool mRequestedShutdown{ false };

  EventCallback mEventCallback;

  // init/de-init
  std::optional<StartReplayOptions> mReplayOptions;

  rr::BreakStatus *mSavedBreakStatus{ nullptr };

  std::condition_variable mHasReplayCondVar{};
  std::mutex mCondVarMutex{};
  std::string mTraceDir;
  bool mIssuedStartRequest{ false };

  std::mutex mRequestMutex{};
  std::condition_variable mRequestCondVar{};
  bool mHasRequest;

  std::unordered_map<SupervisorSessionEventType, std::function<void()>> mSupervisorEvents{};

  void PublishEvent(const SupervisorEvent &evt) noexcept;
  void PublishSessionEvent(SupervisorSessionEventType type,
    const TraceFrameTaskContext &taskContext = TraceFrameTaskContext::None()) noexcept;

  void InitializeDebugSession();
  void SetWillNeedResume(const rr::BreakStatus *break_status);
  StopKind CheckStopKind(pid_t recTid, int syscallNumber, const rr::TraceFrame &traceFrame) noexcept;
  std::optional<SupervisorEvent> FromReplayResult(const rr::ReplayResult &result, ResumeReplay &replay_request);

  rr::ReplayResult PerformResume();
  bool InterruptCheck();

  void NotifyResumed() noexcept;

  explicit ReplaySupervisor(const RRInitOptions &initOptions) noexcept;

public:
  static ReplaySupervisor *Create(SessionId sessionId, const RRInitOptions &initOptions = {}) noexcept;
  void StartReplay(const char *traceDir, std::function<void()> onStartCompleted) noexcept;
  std::vector<Pid> CurrentLiveProcesses() const noexcept;
  Session *CachedSupervisor(Tid taskLeader) const noexcept;
  void AddSupervisor(NonNullPtr<Session> session) noexcept;

  void RegisterStopsForProcess(Pid pid) noexcept;
  bool IsTracing(Pid pid) noexcept;
  bool IsIgnoring(Pid pid) noexcept;

  void WaitForEvent() noexcept;
  mdb::Publisher<void> mEvents;

  void ProcessRequests();

  // Whether or not this supervisor is responsible for a trace that's been
  // loaded & started. Not the same as `is_replaying` which signals if we are
  // doing replay steps at the moment.
  bool HasSession() const;
  bool IsReplaying() const;

  void InitLibrary();
  void Shutdown();

  /// Replay control
  bool RequestResume(ResumeReplay resume_tracee);

  // A front end is going to need this, for instance to determine if "do we
  // need to step over a breakpoint the next thing we do?" One solution would
  // be have `SupervisorLibrary` actually be responsible for managing
  // breakpoints like that, but debuggers handle this themselves, so it would
  // be weird from their perspective and have to really edge case this. By
  // asking "who is resuming next", the debugger can see that it needs to step
  // over a breakpoint, because it's stopped at one and act accordingly.
  pid_t GetTaskToResume() const;

  /*
   * `rec_tid` is the task who will be reported in the stop event, regardless of
   * who's actually executing in the internal supervisor.
   */
  bool RequestInterrupt(pid_t rec_tid);

  /// Read & Write operations
  int64_t ReadMemory(pid_t rec_tid, uintptr_t address, int buf_size, void *buf);

  RegisterCacheData ReadRegisters(pid_t rec_tid);

  bool SetBreakpoint(pid_t rec_tid, BreakpointRequest req);
  bool SetWatchpoint(pid_t rec_tid, WatchpointRequest req);
  bool RemoveBreakpoint(pid_t rec_tid, BreakpointRequest req);
  bool RemoveWatchpoint(pid_t rec_tid, WatchpointRequest req);
  const char *ExecedFile(pid_t rec_tid) const;
  const std::vector<std::uint8_t> &GetAuxv(pid_t rec_tid);
  rr::ReplayTask *GetTask(pid_t rec_tid) const;
};
} // namespace mdb::tc::replay

namespace mdbrr = mdb::tc::replay;