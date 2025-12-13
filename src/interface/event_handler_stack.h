#pragma once

#include <common/typedefs.h>
#include <functional>
#include <lib/stack.h>

namespace mdb {
enum class EventState : u8
{
  Unhandled,
  Handled,
  Defer,
};

template <typename Evt> using EventHandler = std::function<EventState(const Evt &evt)>;

template <typename Evt> class EventHandlerStack
{
public:
  using Handler = EventHandler<Evt>;
  using HandlerStack = InlineStack<Handler, 16>;

  constexpr bool
  HasEventHandler() const noexcept
  {
    return !mEventHandlerStack.Empty();
  }

  constexpr EventState
  ProcessEvent(const Evt &evt) noexcept
  {
    if (mEventHandlerStack.Empty()) {
      return EventState::Unhandled;
    }

    for (const auto &handler : mEventHandlerStack.StackWalkDown()) {
      if (const auto result = handler(evt); result != EventState::Unhandled) {
        return result;
      }
    }

    return EventState::Unhandled;
  }

  constexpr bool
  PushEventHandler(Handler &&handler) noexcept
  {
    if (mEventHandlerStack.Size() == mEventHandlerStack.Capacity()) {
      PANIC("Event handler stack can't hold more handlers");
    }
    mEventHandlerStack.Push(std::move(handler));
    return true;
  }

  constexpr void
  Pop() noexcept
  {
    mEventHandlerStack.Pop();
  }

private:
  HandlerStack mEventHandlerStack{};
};
} // namespace mdb