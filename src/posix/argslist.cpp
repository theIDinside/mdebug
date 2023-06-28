#include "argslist.h"
#include "../common.h"

PosixArgsList::PosixArgsList(std::vector<std::string> &&args) noexcept : m_args(std::move(args)) { init(); }

Command
PosixArgsList::get_command() const noexcept
{
  auto cmd = m_cstr_args.front();
  auto args = std::span{m_cstr_args}.subspan(1);

  const auto result = Command{.command = cmd, .args = (char* const*)args.data()};
  #ifdef MDB_DEBUG
  if(*(const char**)args.back() != nullptr) {
    PANIC("Malformed posix arguments list - must be terminated by nullptr");
  }
  #endif
  return result;
}

const char *
PosixArgsList::get_arg(std::size_t index) const noexcept
{
  return m_cstr_args[index];
}

void
PosixArgsList::init()
{
  m_args.push_back({});
  for (const auto &str : m_args) {
    m_cstr_args.push_back(str.c_str());
  }
}