#pragma once

#include <sys/types.h>


enum class StopEventType {
  Syscall
};

struct Event {
  pid_t event_for;
  StopEventType evt_type;
};