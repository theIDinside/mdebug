#pragma once

#include "ptrace.h"
namespace ui {
struct UICommand;
}

enum class EventType
{
  WaitStatus,
  NewTask,
  Command
};

struct Wait
{
  int pid;
  int tid;
};

struct Event
{
  Tid process_group;
  EventType type;
  union
  {
    TaskWaitResult wait;
    ui::UICommand *cmd;
  };
};

void push_event(Event);
Event poll_event();