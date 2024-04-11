#pragma once

#include "utils/macros.h"
#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <sys/types.h>
#include <type_traits>
#include <utils/algorithm.h>
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
  explicit Step(TraceeController &tc, int tid, std::string_view msg) noexcept;
  void send() noexcept override;

private:
  TraceeController &tc;
  int tid;
  std::string_view msg;
};

class BreakpointHit : public StopEventNotification
{
public:
  explicit BreakpointHit(TraceeController &tc, int bp_id, int tid) noexcept;
  void send() noexcept override;

private:
  TraceeController &tc;
  int bp_id;
  int tid;
};

class SignalStop : public StopEventNotification
{
public:
  SignalStop(TraceeController &tc, int signal, int tid) noexcept;
  void send() noexcept override;

private:
  TraceeController &tc;
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
    return SubscriberIdentity{t};
  }

  template <typename T>
  static constexpr SubscriberIdentity
  Of(const T *t) noexcept
  {
    return SubscriberIdentity{t};
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

template <typename EventData> class Publisher
{
  using SubscriberAction = std::function<bool(EventData)>;

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
  subscribe(SubscriberIdentity identity, Fn &&fn) noexcept
  {
    ASSERT(utils::none_of(subscribers, [&identity](auto &c) { return identity == c.identity; }),
           "Expected Identity to be a unique value");
    subscribers.emplace_back(identity, std::move(fn));
  }

  void
  unsubscribe(SubscriberIdentity identity) noexcept
  {

    if (auto it = std::find_if(subscribers.begin(), subscribers.end(),
                               [&identity](const auto &sub) { return sub.identity == identity; });
        it != std::end(subscribers)) {
      subscribers.erase(it);
    }
  }

  template <typename Fn>
  void
  once(Fn &&fn) noexcept
  {
    sub_once.push_back(std::move(fn));
  }

  void
  emit(const EventData &evt) noexcept
    requires(!std::is_void_v<EventData>)
  {
    for (auto &&fn : sub_once) {
      fn(evt);
    }
    sub_once.clear();

    std::vector<SubscriberIdentity> remove{};
    remove.reserve(subscribers.size());
    for (auto &sub : subscribers) {
      const auto keep = sub.fn(evt);
      if (!keep) {
        remove.push_back(sub.identity);
      }
    }

    for (auto i : remove) {
      unsubscribe(i);
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
  subscribe(SubscriberIdentity identity, Fn &&fn) noexcept
  {
    ASSERT(utils::none_of(subscribers, [&identity](auto &c) { return identity == c.identity; }),
           "Expected Identity to be a unique value");
    subscribers.emplace_back(identity, std::move(fn));
  }

  void
  unsubscribe(SubscriberIdentity identity) noexcept
  {
    auto it = std::find_if(subscribers.begin(), subscribers.end(),
                           [&identity](auto &sub) { return sub.identity == identity; });
    if (it != std::end(subscribers)) {
      subscribers.erase(it);
    }
  }

  template <typename Fn>
  void
  once(Fn &&fn) noexcept
  {
    sub_once.push_back(std::move(fn));
  }

  void
  emit() noexcept
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