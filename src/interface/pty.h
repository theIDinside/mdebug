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
  std::string mName;
  int mFd;
};

struct PtyParentResult
{
  std::string mPtyName;
  pid_t mPid;
  std::optional<int> mFd;
};

struct ParentResult
{
  pid_t mChildPid;
};

std::optional<MasterPty> open_pty_master() noexcept;
std::variant<pid_t, PtyParentResult, ParentResult> ptyFork(bool dontDuplicateStdio, const termios *slave_termios,
                                                           const winsize *slave_winsize);
} // namespace mdb