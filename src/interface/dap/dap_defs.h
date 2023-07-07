#pragma once

#include <cstdint>
#include <string_view>

namespace ui::dap {

enum class Command : std::uint8_t
{
  Attach = 0,
  BreakpointLocations,
  Completions,
  ConfigurationDone,
  Continue,
  CustomRequest,
  DataBreakpointInfo,
  Disassemble,
  Disconnect,
  Evaluate,
  ExceptionInfo,
  Goto,
  GotoTargets,
  Initialize,
  Launch,
  LoadedSources,
  Modules,
  Next,
  Pause,
  ReadMemory,
  Restart,
  RestartFrame,
  ReverseContinue,
  Scopes,
  SetBreakpoints,
  SetDataBreakpoints,
  SetExceptionBreakpoints,
  SetExpression,
  SetFunctionBreakpoints,
  SetInstructionBreakpoints,
  SetVariable,
  Source,
  StackTrace,
  StepBack,
  StepIn,
  StepInTargets,
  StepOut,
  Terminate,
  TerminateThreads,
  Threads,
  Variables,
  WriteMemory,
  UNKNOWN
};

// We sent events, we never receive them, so an "UNKNOWN" value is unnecessary.
// or better put; Events are an "output" type only.
enum class Events : std::uint8_t
{
  Breakpoint = 0,
  Capabilities,
  Continued,
  Exited,
  Initialized,
  Invalidated,
  LoadedSource,
  Memory,
  Module,
  Output,
  Process,
  ProgressEnd,
  ProgressStart,
  ProgressUpdate,
  Stopped,
  Terminated,
  Thread,
};

} // namespace ui::dap