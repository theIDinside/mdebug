#pragma once

#include "bp.h"
#include "common.h"
#include "event_queue.h"
#include "interface/attach_args.h"
#include "interface/dap/interface.h"
#include "interface/tracee_command/gdb_remote_commander.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "mdb_config.h"
#include "notify_pipe.h"
#include "ptrace.h"
#include "utils/immutable.h"
#include <queue>
#include <sys/ioctl.h>
#include <termios.h>
#include <unordered_map>

class ObjectFile;
class SymbolFile;
class TraceeController;

using Pid = pid_t;
using Tid = pid_t;

namespace gdb {
class RemoteConnection;
struct RemoteSettings;
} // namespace gdb

namespace ui::dap {
class DAP;
struct Event;
struct Scope;
} // namespace ui::dap

namespace cmd {
class Command;
};

namespace ui {
struct UICommand;
}

enum class Proceed
{
  Stop,
  Resume
};

struct LWP;
struct TaskInfo;

using BreakpointSpecId = u32;

using VarRefKey = u32;

struct VariableObject
{
};

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

/** -- A Singleton instance --. There can only be one. (well, there should only be one.)*/
class Tracer
{
public:
  static termios original_tty;
  static winsize ws;
  static Tracer *Instance;
  static bool KeepAlive;
  static bool use_traceme;
  friend struct ui::UICommand;

  Tracer(utils::Notifier::ReadEnd io_thread_pipe, utils::NotifyManager *events_notifier,
         sys::DebuggerConfiguration) noexcept;

  void add_target_set_current(const tc::InterfaceConfig &config, TargetSession session) noexcept;
  void load_and_process_objfile(pid_t target, const Path &objfile_path) noexcept;
  TraceeController *get_controller(pid_t pid) noexcept;
  // TODO(simon): This should be removed. When multiprocess becomes a thing _all_ supervisor access must happen via
  // a process id or some other handle/id. this is just for convenience when developing the product, really.
  void config_done(ui::dap::DebugAdapterClient *client) noexcept;
  CoreEvent *process_waitevent_to_core(Tid process_group, TaskWaitResult wait_res) noexcept;
  void handle_command(ui::UICommand *cmd) noexcept;
  void handle_core_event(const CoreEvent *evt) noexcept;
  void handle_init_event(const CoreEvent *evt) noexcept;

  void set_ui(ui::dap::DAP *dap) noexcept;
  void kill_ui() noexcept;

  /** Receives a command and places it on the command queue to be executed. Thread-safe, but if re-entrant will
   * hang. */
  void accept_command(ui::UICommand *cmd) noexcept;
  TraceeController *new_supervisor(std::unique_ptr<TraceeController> &&tc) noexcept;
  void launch(ui::dap::DebugAdapterClient *client, bool stopAtEntry, Path program,
              std::span<const std::string> prog_args) noexcept;
  bool attach(const AttachArgs &args) noexcept;
  bool remote_attach_init(tc::GdbRemoteCommander &tc) noexcept;
  void detach_target(std::unique_ptr<TraceeController> &&target, bool resume_on_detach) noexcept;

  std::shared_ptr<SymbolFile> LookupSymbolfile(const std::filesystem::path &path) noexcept;
  const sys::DebuggerConfiguration &getConfig() noexcept;

  const sys::DebuggerConfiguration &get_configuration() const noexcept;
  std::shared_ptr<gdb::RemoteConnection>
  connectToRemoteGdb(const tc::GdbRemoteCfg &config, const std::optional<gdb::RemoteSettings> &settings) noexcept;
  NonNullPtr<TraceeController> set_current_to_latest_target() noexcept;

  u32 new_breakpoint_id() noexcept;
  VarRefKey new_key() noexcept;
  VariableContext var_context(VarRefKey varRefKey) noexcept;
  VarRefKey new_var_context(TraceeController &tc, TaskInfo &t, u32 frameId, SymbolFile *file) noexcept;
  void set_var_context(VariableContext ctx) noexcept;
  u32 clone_from_var_context(const VariableContext &ctx) noexcept;
  void destroy_reference(VarRefKey key) noexcept;
  std::vector<std::unique_ptr<TraceeController>>::iterator
  find_controller_by_dap(ui::dap::DebugAdapterClient *client) noexcept;

  template <typename Predicate>
  bool
  erase_target(Predicate &&fn)
  {
    auto it = std::find_if(targets.begin(), targets.end(), std::move(fn));
    const bool erased = it != std::end(targets);
#ifdef MDB_DEBUG
    DBGLOG(core, "found tracer to delete: {}", erased);
#endif
    targets.erase(it);
    return erased;
  }

  std::vector<std::unique_ptr<TraceeController>> targets;
  ui::dap::DAP *dap;

  bool TraceExitConfigured{false};

private:
  [[maybe_unused]] tc::ProcessedStopEvent process_core_event(TraceeController &tc,
                                                             const CoreEvent *event) noexcept;
  TraceeController *current_target{nullptr};
  u32 breakpoint_ids{0};
  VarRefKey id_counter{0};
  std::unordered_map<VarRefKey, VariableContext> refContext{};
  SpinLock command_queue_lock;
  std::queue<ui::UICommand *> command_queue;
  utils::Notifier::ReadEnd io_thread_pipe;
  bool already_launched;
  utils::NotifyManager *events_notifier;
  sys::DebuggerConfiguration config;
};
