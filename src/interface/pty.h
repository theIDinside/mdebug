/** LICENSE TEMPLATE */
#pragma once

#include <optional>
#include <string>
#include <sys/ioctl.h>
#include <termios.h>
#include <variant>
namespace mdb {
struct MasterPty
{
  std::string name;
  int fd;
};

struct PtyParentResult
{
  std::string pty_name;
  pid_t pid;
  std::optional<int> fd;
};

struct ParentResult
{
  pid_t child_pid;
};

std::optional<MasterPty> open_pty_master() noexcept;
std::variant<pid_t, PtyParentResult, ParentResult> pty_fork(bool dontDuplicateStdio, const termios *slave_termios,
                                                            const winsize *slave_winsize);
} // namespace mdb