/** LICENSE TEMPLATE */
#pragma once

#include "bp.h"
#include "dap_defs.h"
#include "types.h"
#include <interface/ui_result.h>
#include <symbolication/block.h>

namespace mdb {
enum class SharedObjectSymbols : u8;
struct SharedObject;

struct Clone;

constexpr std::string_view LOADER_STATE = "_r_debug_extended";

enum class SharedObjectSymbols : u8
{
  Minimum,
  Full,
  None,
};

constexpr auto
SharedObjectSymbolInfo(SharedObjectSymbols sos) -> std::string_view
{
  switch (sos) {
  case SharedObjectSymbols::Minimum:
    return "Minimal symbols loaded";
  case SharedObjectSymbols::Full:
    return "DWARF & Minimal symbols loaded";
  case SharedObjectSymbols::None:
    return "No symbols loaded";
  }
  MIDAS_UNREACHABLE
}

namespace ui::dap {

enum ChangeEvent : u8
{
  New = 0,
  Changed = 1,
  Removed = 2,
};

struct InitializedEvent final : public ui::UIResult
{
  InitializedEvent(SessionId sessionId, std::optional<SessionId> processId) noexcept
      : ui::UIResult(sessionId), mProcessId(processId)
  {
  }
  ~InitializedEvent() noexcept final = default;
  std::optional<SessionId> mProcessId;
  std::pmr::string Serialize(int monotonicId, std::pmr::memory_resource *allocator = nullptr) const noexcept final;
};

struct TerminatedEvent final : public ui::UIResult
{
  TerminatedEvent(SessionId pid) noexcept : ui::UIResult(pid) {}
  ~TerminatedEvent() noexcept final = default;
  std::pmr::string Serialize(int monotonicId, std::pmr::memory_resource *allocator = nullptr) const noexcept final;
};

static constexpr std::string_view reasons[3]{ "new", "changed", "removed" };
// Module event: https://microsoft.github.io/debug-adapter-protocol/specification#Events_Module
struct ModuleEvent final : public ui::UIResult
{
  ModuleEvent(SessionId sessionId,
    std::string_view id,
    std::string_view reason,
    std::string &&name,
    Path &&path,
    std::optional<std::string> &&symbolFilePath,
    std::optional<std::string> &&version,
    AddressRange range,
    SharedObjectSymbols sharedObjects) noexcept;

  ModuleEvent(SessionId sessionId, std::string_view reason, const ObjectFile &objectFile) noexcept;
  ModuleEvent(SessionId sessionId, std::string_view reason, const SymbolFile &symbolFile) noexcept;
  std::string_view mObjectFileId;
  std::string_view mReason;
  std::string mName;
  Path mPath;
  AddressRange mAddressRange;
  SharedObjectSymbols mSharedObjectFiles;
  std::optional<std::string> mSymbolObjectFilePath;
  std::optional<std::string> version;

  std::pmr::string Serialize(int monotonicid, std::pmr::memory_resource *allocator = nullptr) const noexcept final;
};

struct ContinuedEvent final : public ui::UIResult
{
  // threadId
  int mThreadId;
  // allThreadsContinued
  bool mAllThreadsContinued;
  ContinuedEvent(SessionId pid, Tid tid, bool allThreads) noexcept;
  std::pmr::string Serialize(int monotonicid, std::pmr::memory_resource *allocator = nullptr) const noexcept final;
};

struct CustomEvent final : public ui::UIResult
{
  std::string mCustomEventName;
  std::string mSerializedBody;
  /// `serializedBodyContents`, must contain the brackets around the JSON object, so must be `{ ... }`
  CustomEvent(SessionId pid, std::string name, std::string serializedBodyContents) noexcept
      : ui::UIResult(pid), mCustomEventName(std::move(name)), mSerializedBody(std::move(serializedBodyContents))
  {
  }
  std::pmr::string Serialize(int monotonicid, std::pmr::memory_resource *allocator = nullptr) const noexcept final;
};

struct Process final : public ui::UIResult
{
  std::string mName;
  Pid mProcessId;
  bool mIsLocal;
  Process(SessionId parentSessionId, Pid pid, std::string name, bool isLocal) noexcept;
  std::pmr::string Serialize(int monotonicid, std::pmr::memory_resource *allocator = nullptr) const noexcept final;
};

struct ExitedEvent final : public ui::UIResult
{
  // exitCode
  int mExitCode;
  ExitedEvent(SessionId pid, int exitCode) noexcept;
  std::pmr::string Serialize(int monotonicid, std::pmr::memory_resource *allocator = nullptr) const noexcept final;
};

struct ThreadEvent final : public ui::UIResult
{
  ThreadEvent(SessionId sessionId, ThreadReason reason, Tid tid) noexcept;
  ThreadEvent(SessionId sessionId, const Clone &event) noexcept;
  ~ThreadEvent() noexcept override = default;
  std::pmr::string Serialize(int monotonicid, std::pmr::memory_resource *allocator = nullptr) const noexcept final;
  ThreadReason mReason;
  Tid mTid;
};

struct StoppedEvent final : public ui::UIResult
{
  ~StoppedEvent() noexcept override = default;
  StoppedEvent(SessionId sessionId,
    StoppedReason reason,
    std::string_view description,
    Tid tid,
    std::vector<int> bps,
    std::string_view text,
    bool allStopped) noexcept;
  StoppedReason mReason;
  // static description
  std::string_view mDescription;
  Tid mTid;
  std::vector<int> mBreakpointIds;
  // static additional information, name of exception for instance
  std::string_view mText;
  bool mAllThreadsStopped;
  std::pmr::string Serialize(int monotonicid, std::pmr::memory_resource *allocator = nullptr) const noexcept final;
};

struct BreakpointEvent final : public ui::UIResult
{
  std::string_view mReason;
  std::optional<std::string> mMessage;
  const UserBreakpoint *mBreakpoint;
  BreakpointEvent(SessionId sessionId,
    std::string_view reason,
    std::optional<std::string> message,
    const UserBreakpoint *breakpoint) noexcept;
  ~BreakpointEvent() override = default;
  std::pmr::string Serialize(int monotonicid, std::pmr::memory_resource *allocator = nullptr) const noexcept final;
};

struct OutputEvent final : public ui::UIResult
{
  ~OutputEvent() noexcept override = default;
  OutputEvent(SessionId pid, std::string_view category, std::string &&output) noexcept;

  std::string_view mCategory; // static category strings exist, we always pass literals to this
  std::string mOutput;
  std::pmr::string Serialize(int monotonicid, std::pmr::memory_resource *allocator) const noexcept final;
};

}; // namespace ui::dap
} // namespace mdb