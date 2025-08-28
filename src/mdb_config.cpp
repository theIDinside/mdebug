/** LICENSE TEMPLATE */
#include "mdb_config.h"
#include "utils/logger.h"
#include <charconv>
#include <filesystem>
#include <getopt.h>
#include <string_view>
#include <sys/user.h>
#include <thread>
#include <unistd.h>

namespace mdb::sys {

std::optional<int>
parse_int(std::string_view str)
{
  int result{};
  auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), result);

  if (ec == std::errc()) {
    return result;
  } else {
    return std::nullopt;
  }
}

int
DebuggerConfiguration::ThreadPoolSize() const noexcept
{
  constexpr auto get_default = []() {
    const auto cpus = std::thread::hardware_concurrency();
    return cpus > 4 ? cpus / 2 : cpus;
  };
  return mThreadPoolSize.value_or(get_default());
}

const Path &
DebuggerConfiguration::LogDirectory() const noexcept
{
  if (mLogDirectory.empty()) {
    static Path currentDir = std::filesystem::current_path();
    return currentDir;
  }
  return mLogDirectory;
}

} // namespace mdb::sys