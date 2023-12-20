#pragma once

#include <memory>
#include <sys/types.h>
#include <vector>

struct TraceeController;

class StopEventNotification
{
public:
  virtual ~StopEventNotification() = default;
  virtual void send() noexcept = 0;
};

class Step : public StopEventNotification
{
public:
  explicit Step(TraceeController *tc, int tid, std::string_view msg) noexcept;
  void send() noexcept override;

private:
  TraceeController *tc;
  int tid;
  std::string_view msg;
};

class BreakpointHit : public StopEventNotification
{
public:
  explicit BreakpointHit(TraceeController *tc, int bp_id, int tid) noexcept;
  void send() noexcept override;

private:
  TraceeController *tc;
  int bp_id;
  int tid;
};

class SignalStop : public StopEventNotification
{
public:
  SignalStop(TraceeController *tc, int signal, int tid) noexcept;
  void send() noexcept override;

private:
  TraceeController *tc;
  int signal;
  int tid;
};

class StopObserver
{
public:
  void send_notifications() noexcept;

  template <typename NotificationType, typename... Args>
  constexpr void
  add_notification(Args... args) noexcept
  {
    notifications.emplace_back(std::make_unique<NotificationType>(std::forward<Args>(args)...));
  }

private:
  std::vector<std::unique_ptr<StopEventNotification>> notifications;
};