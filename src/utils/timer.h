#pragma once
#include <chrono>
#include <optional>
#include <string>
#include <string_view>

// Logs time taken between construction of this object and destruction of it (or the time that .stop() was called).
// LoggingTimer takes a channel name and a message - both must be string_views (and such be long lived)
class LoggingTimer
{
public:
  using Clock = std::chrono::high_resolution_clock;
  using TimePoint = std::chrono::time_point<Clock>;
  enum class TimeUnit : std::uint8_t
  {
    Milliseconds,
    Microseconds,
    Nanoseconds
  };

  LoggingTimer(std::string_view channel, std::string_view message,
               TimeUnit unit = TimeUnit::Microseconds) noexcept;
  ~LoggingTimer() noexcept;
  void stop() noexcept;

private:
  std::string_view channel;
  std::string_view message;
  TimeUnit unit;
  TimePoint start;
  std::optional<TimePoint> end;
};