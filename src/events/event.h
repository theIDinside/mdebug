/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common/macros.h>
#include <events/stop_event.h>
#include <utils/algorithm.h>

// stdlib
#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

// system
#include <sys/types.h>

namespace mdb {
namespace tc {
class SupervisorState;
}

class StopEventNotification
{
public:
  virtual ~StopEventNotification() = default;
  virtual void send() noexcept = 0;
};

class Step : public StopEventNotification
{
public:
  explicit Step(tc::SupervisorState &tc, int tid, std::string_view msg) noexcept;
  void send() noexcept override;

private:
  tc::SupervisorState &tc;
  int tid;
  std::string_view msg;
};

class BreakpointHit : public StopEventNotification
{
public:
  explicit BreakpointHit(tc::SupervisorState &tc, int bp_id, int tid) noexcept;
  void send() noexcept override;

private:
  tc::SupervisorState &tc;
  int bp_id;
  int tid;
};

class SignalStop : public StopEventNotification
{
public:
  SignalStop(tc::SupervisorState &tc, int signal, int tid) noexcept;
  void send() noexcept override;

private:
  tc::SupervisorState &tc;
  int signal;
  int tid;
};

class StopObserver
{
public:
  void send_notifications() noexcept;

  template <typename NotificationType, typename... Args>
  constexpr void
  add_notification(Args &&...args) noexcept
  {
    notifications.emplace_back(std::make_unique<NotificationType>(std::forward<Args>(args)...));
  }

private:
  std::vector<std::unique_ptr<StopEventNotification>> notifications;
};

struct SubscriberIdentity
{

  constexpr SubscriberIdentity(const SubscriberIdentity &) = default;
  constexpr SubscriberIdentity &operator=(const SubscriberIdentity &) = default;
  constexpr SubscriberIdentity(SubscriberIdentity &&) = default;
  constexpr SubscriberIdentity &operator=(SubscriberIdentity &&) = default;

  template <typename T>
  constexpr explicit SubscriberIdentity(T *obj) noexcept : addr(reinterpret_cast<std::uintptr_t>(obj))
  {
  }
  template <typename T>
  constexpr explicit SubscriberIdentity(const T *obj) noexcept : addr(reinterpret_cast<std::uintptr_t>(obj))
  {
  }

  template <typename T>
  static constexpr SubscriberIdentity
  Of(T *t) noexcept
  {
    return SubscriberIdentity{ t };
  }

  template <typename T>
  static constexpr SubscriberIdentity
  Of(const T *t) noexcept
  {
    return SubscriberIdentity{ t };
  }

  std::uintptr_t addr;

  constexpr friend auto operator<=>(const SubscriberIdentity &l, const SubscriberIdentity &r) noexcept = default;
  constexpr friend auto
  operator==(const SubscriberIdentity &l, const SubscriberIdentity &r) noexcept
  {
    return l.addr == r.addr;
  }

  constexpr friend auto
  operator!=(const SubscriberIdentity &l, const SubscriberIdentity &r) noexcept
  {
    return !(l == r);
  }
};

static constexpr bool
KeepSubscriber() noexcept
{
  return true;
}
static constexpr bool
RemoveSubscriber() noexcept
{
  return false;
}

template <typename... EventData> class Publisher
{
  using SubscriberAction = std::function<void(EventData...)>;

  struct Subscriber
  {
    NO_COPY_DEFAULTED_MOVE(Subscriber);
    Subscriber(SubscriberIdentity id, SubscriberAction &&fn) noexcept : identity(id), fn(std::move(fn)) {}
    SubscriberIdentity identity;
    SubscriberAction fn;
  };

  std::vector<Subscriber> subscribers{};
  std::vector<SubscriberAction> sub_once{};

public:
  void
  Subscribe(SubscriberIdentity identity, SubscriberAction &&fn) noexcept
  {
    MDB_ASSERT(mdb::none_of(subscribers, [&identity](auto &c) { return identity == c.identity; }),
      "Expected Identity to be a unique value");
    subscribers.emplace_back(identity, std::move(fn));
  }

  void
  Unsubscribe(SubscriberIdentity identity) noexcept
  {
    if (auto it = std::find_if(subscribers.begin(),
          subscribers.end(),
          [&identity](const auto &sub) { return sub.identity == identity; });
      it != std::end(subscribers)) {
      subscribers.erase(it);
    }
  }

  void
  Once(SubscriberAction &&fn) noexcept
  {
    sub_once.push_back(std::move(fn));
  }

  void
  Emit(EventData &&...data) noexcept
  {
    for (auto &&fn : sub_once) {
      fn(std::forward<EventData>(data)...);
    }
    sub_once.clear();

    for (auto &sub : subscribers) {
      sub.fn(std::forward<EventData>(data)...);
    }
  }
};

template <> class Publisher<void>
{
  using SubscriberAction = std::function<void()>;

  struct Subscriber
  {
    NO_COPY_DEFAULTED_MOVE(Subscriber);
    Subscriber(SubscriberIdentity id, SubscriberAction &&fn) noexcept : identity(id), fn(std::move(fn)) {}
    SubscriberIdentity identity;
    SubscriberAction fn;
  };

  std::vector<Subscriber> subscribers{};
  std::vector<SubscriberAction> sub_once{};

public:
  template <typename Fn>
  void
  Subscribe(SubscriberIdentity identity, Fn &&fn) noexcept
  {
    MDB_ASSERT(mdb::none_of(subscribers, [&identity](auto &c) { return identity == c.identity; }),
      "Expected Identity to be a unique value");
    subscribers.emplace_back(identity, std::move(fn));
  }

  void
  Unsubscribe(SubscriberIdentity identity) noexcept
  {
    auto it = std::find_if(
      subscribers.begin(), subscribers.end(), [&identity](auto &sub) { return sub.identity == identity; });
    if (it != std::end(subscribers)) {
      subscribers.erase(it);
    }
  }

  template <typename Fn>
  void
  Once(Fn &&fn) noexcept
  {
    sub_once.push_back(std::move(fn));
  }

  void
  Emit() noexcept
  {
    for (auto &&fn : sub_once) {
      fn();
    }
    sub_once.clear();

    for (auto &sub : subscribers) {
      sub.fn();
    }
  }
};
} // namespace mdb

namespace mdb::pub {
#define EACH_FN(EVT, DESC, RET, ...) extern Publisher<__VA_ARGS__> EVT;
FOR_EACH_EVENT(EACH_FN)
#undef EACH_FN
} // namespace mdb::pub
