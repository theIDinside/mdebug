#pragma once

#include "common.h"
#include "interface/ui_result.h"
#include "mdb_config.h"
#include "notify_pipe.h"
#include "ptrace.h"
#include <queue>
#include <sys/ioctl.h>
#include <termios.h>
#include <unordered_map>

struct ObjectFile;
struct TraceeController;

using Pid = pid_t;
using Tid = pid_t;
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
  void add_target_set_current(pid_t task_leader, const Path &path, TargetSession session) noexcept;
  void load_and_process_objfile(pid_t target, const Path &objfile_path) noexcept;
  void thread_exited(LWP lwp, int status) noexcept;
  TraceeController *get_controller(pid_t pid) noexcept;
  TraceeController *get_current() noexcept;
  void config_done() noexcept;
  void handle_wait_event(Tid process_group, TaskWaitResult wait_res) noexcept;
  void handle_command(ui::UICommandPtr cmd) noexcept;

  void wait_for_tracee_events(Tid target) noexcept;
  void set_ui(ui::dap::DAP *dap) noexcept;
  void kill_ui() noexcept;
  void post_event(ui::UIResultPtr obj) noexcept;

  /** Receives a command and places it on the command queue to be executed. Thread-safe, but if re-entrant will
   * hang. */
  void accept_command(ui::UICommand *cmd) noexcept;
  void execute_pending_commands() noexcept;
  void launch(bool stopAtEntry, Path program, std::vector<std::string> prog_args) noexcept;
  void kill_all_targets() noexcept;
  void detach(std::unique_ptr<TraceeController> &&target) noexcept;
  void disconnect() noexcept;

  const sys::DebuggerConfiguration &get_configuration() const noexcept;
  std::vector<std::unique_ptr<TraceeController>> targets;
  ui::dap::DAP *dap;

private:
  TraceeController *current_target = nullptr;
  SpinLock command_queue_lock;
  std::queue<ui::UICommand *> command_queue;
  utils::Notifier::ReadEnd io_thread_pipe;
  bool already_launched;
  utils::NotifyManager *events_notifier;
  sys::DebuggerConfiguration config;
};
