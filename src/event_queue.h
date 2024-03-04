#pragma once

#include "ptrace.h"
#include <utility>
namespace ui {
struct UICommand;
}

enum class EventType
{
  WaitStatus,
  Command,
  DebuggerEvent
};

struct WaitEvent
{
  Tid process_group;
  TaskWaitResult wait;
};

enum class DebuggerEvent
{
  Proceed
};

constexpr std::string_view
to_str(DebuggerEvent evt) noexcept
{
  switch (evt) {
  case DebuggerEvent::Proceed:
    return "DebuggerEvent::Proceed";
  }
  std::unreachable();
}

struct ProceedEvent
{
  Tid tid;
};

struct DebuggerEventData
{
  Tid process_group;
  DebuggerEvent type;
  union
  {
    ProceedEvent proceed;
  };
};

struct Event
{
  EventType type;
  union
  {
    WaitEvent wait;
    DebuggerEventData debugger;
    ui::UICommand *cmd;
  };
};

void push_wait_event(Tid process_group, TaskWaitResult wait_result) noexcept;
void push_command_event(ui::UICommand *cmd) noexcept;
void push_debugger_event(DebuggerEventData &&event) noexcept;

Event poll_event();