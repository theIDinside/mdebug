#include "timer.h"
#include "logger.h"
#include <common.h>

LoggingTimer::LoggingTimer(std::string_view channel, std::string_view message, TimeUnit unit) noexcept
    : channel(channel), message(std::move(message)), unit(unit), start(Clock::now()), end(std::nullopt)
{
}

void
LoggingTimer::stop() noexcept
{
  end = Clock::now();
}

LoggingTimer::~LoggingTimer() noexcept
{
  const auto end_ = end.value_or(Clock::now());
  switch (unit) {
  case TimeUnit::Milliseconds:
    logging::get_logging()->log(channel, fmt::format("[{}]: {}ns", message, millis(start, end_)));
    break;
  case TimeUnit::Microseconds:
    logging::get_logging()->log(channel, fmt::format("[{}]: {}ns", message, micros(start, end_)));
    break;
  case TimeUnit::Nanoseconds:
    logging::get_logging()->log(channel, fmt::format("[{}]: {}ns", message, nanos(start, end_)));
    break;
  }
}