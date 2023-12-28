#pragma once

#include "ptrace.h"
namespace ui {
struct UICommand;
}

enum class EventType
{
  WaitStatus,
  Command
};

struct WaitEvent
{
  Tid process_group;
  TaskWaitResult wait;
};

struct Event
{
  EventType type;
  union
  {
    WaitEvent wait;
    ui::UICommand *cmd;
  };
};

void push_wait_event(Tid process_group, TaskWaitResult wait_result) noexcept;
void push_command_event(ui::UICommand *cmd) noexcept;

Event poll_event();