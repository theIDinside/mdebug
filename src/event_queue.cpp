#include "event_queue.h"
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>

// todo(simon): Major refactor. This file is just a proto-prototype event queue system, to replace the more hacky
// system that was before.

static std::mutex event_queue_mutex{};
static std::mutex event_queue_wait_mutex{};
static std::condition_variable cv{};
static std::queue<Event> events{};

static void
push_event(Event e)
{
  std::lock_guard lock(event_queue_mutex);
  events.push(e);
  cv.notify_all();
}

void
push_wait_event(Tid process_group, TaskWaitResult wait_result) noexcept
{
  push_event(Event{.type = EventType::WaitStatus, .wait = {.process_group = process_group, .wait = wait_result}});
}

void
push_command_event(ui::UICommand *cmd) noexcept
{
  push_event(Event{.type = EventType::Command, .cmd = cmd});
}

Event
poll_event()
{
  while (events.empty()) {
    std::unique_lock lock(event_queue_wait_mutex);
    cv.wait_for(lock, std::chrono::milliseconds{10});
  }

  Event evt;
  {
    std::lock_guard lock(event_queue_mutex);
    evt = events.front();
    events.pop();
  }
  return evt;
}