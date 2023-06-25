#pragma once
#include <span>
#include <string>
#include <string_view>
#include <vector>

/**
 * Posix command; a command string with a nullptr terminated list of strings
 */
struct Command
{
  const char *const command;
  char *const *args;
};

/**
 * Utility class to be able to be passed to POSIX syscalls and utilities.
 */
class PosixArgsList
{
public:

  explicit PosixArgsList(std::vector<std::string> &&args) noexcept;
  Command get_command() const noexcept;
  const char *get_arg(std::size_t index) const noexcept;

private:
  void init();
  std::vector<std::string> m_args;
  std::vector<const char *> m_cstr_args;
};