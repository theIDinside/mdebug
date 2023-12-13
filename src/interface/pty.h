#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <sys/ioctl.h>
#include <termios.h>
#include <variant>

struct MasterPty
{
  std::string name;
  int fd;
};

struct PtyParentResult
{
  std::string pty_name;
  pid_t pid;
  int fd;
};

std::optional<MasterPty> open_pty_master() noexcept;
std::variant<pid_t, PtyParentResult> pty_fork(const termios *slave_termios, const winsize *slave_winsize);