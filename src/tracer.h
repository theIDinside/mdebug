#pragma once

#include "common.h"
#include "event_queue.h"
#include "interface/attach_args.h"
#include "interface/tracee_command/gdb_remote_commander.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "interface/ui_result.h"
#include "mdb_config.h"
#include "notify_pipe.h"
#include "ptrace.h"
#include "utils/immutable.h"
#include <queue>
#include <sys/ioctl.h>
#include <termios.h>
#include <unordered_map>

struct ObjectFile;
class SymbolFile;
struct TraceeController;

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
  void thread_exited(LWP lwp, int status) noexcept;
  TraceeController *get_controller(pid_t pid) noexcept;
  // TODO(simon): This should be removed. When multiprocess becomes a thing _all_ supervisor access must happen via
  // a process id or some other handle/id. this is just for convenience when developing the product, really.
  NonNullPtr<TraceeController> get_current() noexcept;
  void config_done() noexcept;
  CoreEvent *handle_wait_event_2(Tid process_group, TaskWaitResult wait_res) noexcept;
  void handle_command(ui::UICommandPtr cmd) noexcept;
  void handle_core_event(const CoreEvent *evt) noexcept;
  void handle_init_event(const CoreEvent *evt) noexcept;

  void set_ui(ui::dap::DAP *dap) noexcept;
  void kill_ui() noexcept;
  void post_event(ui::UIResultPtr obj) noexcept;

  /** Receives a command and places it on the command queue to be executed. Thread-safe, but if re-entrant will
   * hang. */
  void accept_command(ui::UICommand *cmd) noexcept;
  void execute_pending_commands() noexcept;
  void launch(bool stopAtEntry, Path program, std::vector<std::string> prog_args) noexcept;
  bool attach(const AttachArgs &args) noexcept;
  bool remote_attach_init(tc::GdbRemoteCommander &tc) noexcept;
  void detach_target(std::unique_ptr<TraceeController> &&target, bool resume_on_detach) noexcept;
  void disconnect(bool terminate) noexcept;

  std::shared_ptr<SymbolFile> LookupSymbolfile(const std::filesystem::path &path) noexcept;
  const sys::DebuggerConfiguration &getConfig() noexcept;

  const sys::DebuggerConfiguration &get_configuration() const noexcept;
  std::shared_ptr<gdb::RemoteConnection>
  connectToRemoteGdb(const tc::GdbRemoteCfg &config, const std::optional<gdb::RemoteSettings> &settings) noexcept;
  NonNullPtr<TraceeController> set_current_to_latest_target() noexcept;

  std::vector<std::unique_ptr<TraceeController>> targets;
  ui::dap::DAP *dap;

private:
  [[maybe_unused]] bool process_core_event_determine_proceed(TraceeController &tc,
                                                             const CoreEvent *event) noexcept;
  TraceeController *current_target = nullptr;
  SpinLock command_queue_lock;
  std::queue<ui::UICommand *> command_queue;
  utils::Notifier::ReadEnd io_thread_pipe;
  bool already_launched;
  utils::NotifyManager *events_notifier;
  sys::DebuggerConfiguration config;
};
