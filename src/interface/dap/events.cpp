/** LICENSE TEMPLATE */
#include "events.h"
#include "fmt/core.h"
#include "fmt/format.h"
#include "fmt/ranges.h"
#include "nlohmann/json.hpp"
#include <event_queue.h>
#include <symbolication/objfile.h>

namespace mdb::ui::dap {
#define ReturnFormatted(formatString, ...)                                                                        \
  std::pmr::string result{arenaAllocator};                                                                        \
  fmt::format_to(std::back_inserter(result), formatString __VA_OPT__(, ) __VA_ARGS__);                            \
  return result
// std::pmr::string Serialize(int monotonic_id, std::pmr::memory_resource* allocator=nullptr) const noexcept final;
std::pmr::string
InitializedEvent::Serialize(int, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  // The debug adapter supporting client, can now map the sessionId it provided to us, to the `processId` so that
  // it can know, for what session, the process is mapped to.
  ReturnFormatted(
    R"({{"seq":{},"processId":{},"type":"event","event":"initialized", "body":{{"sessionId":"{}", "processId":{}}}}})",
    1, mPid, mSessionUUID, mPid);
}

std::pmr::string
TerminatedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(R"({{"seq":{},"processId":{},"type":"event", "event":"terminated" }})", seq, mPid);
}

ModuleEvent::ModuleEvent(Pid pid, std::string_view id, std::string_view reason, std::string &&name, Path &&path,
                         std::optional<std::string> &&symbolFilePath, std::optional<std::string> &&version,
                         AddressRange range, SharedObjectSymbols sharedObjects) noexcept
    : UIResult(pid), mObjectFileId(id), mReason(reason), mName(std::move(name)), mPath(std::move(path)),
      mAddressRange(range), mSharedObjectFiles(sharedObjects), mSymbolObjectFilePath(std::move(symbolFilePath)),
      version(std::move(version))
{
}

ModuleEvent::ModuleEvent(Pid pid, std::string_view reason, const ObjectFile &object_file) noexcept
    : UIResult(pid), mObjectFileId(object_file.GetObjectFileId()), mReason(reason),
      mName(object_file.GetFilePath().filename()), mPath(object_file.GetFilePath()),
      mAddressRange(object_file.GetAddressRange()), mSharedObjectFiles(SharedObjectSymbols::None),
      mSymbolObjectFilePath(object_file.GetFilePath()), version()
{
}

ModuleEvent::ModuleEvent(Pid pid, std::string_view reason, const SymbolFile &symbol_file) noexcept
    : UIResult(pid), mObjectFileId(symbol_file.mSymbolObjectFileId), mReason(reason),
      mName(symbol_file.GetObjectFilePath().filename()), mPath(symbol_file.GetObjectFilePath()),
      mAddressRange(symbol_file.mPcBounds), mSharedObjectFiles(SharedObjectSymbols::Full),
      mSymbolObjectFilePath(symbol_file.GetObjectFilePath().c_str()), version()
{
}

template <typename T>
auto
format_optional(const std::optional<T> &opt, bool with_quotes) noexcept -> std::string
{
  if (with_quotes) {
    return opt.transform([](auto &value) { return fmt::format(R"("{}")", value); }).value_or("null");
  } else {
    return opt.transform([](auto &value) { return fmt::format(R"({})", value); }).value_or("null");
  }
}

std::pmr::string
ModuleEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  auto out = fmt::memory_buffer();
  std::pmr::string result{arenaAllocator};

  auto it = fmt::format_to(
    std::back_inserter(result),
    R"({{"seq":{},"processId":{},"type":"event","event":"module","body":{{"reason":"{}", "module":{{"id":"{}","name":"{}","path":"{}")",
    seq, mPid, mReason, mObjectFileId, mName, mPath.c_str());

  if (version) {
    it = fmt::format_to(it, R"(,"version":"{}")", *version);
  }
  it = fmt::format_to(it, R"(,"symbolStatus":"{}")", SharedObjectSymbolInfo(mSharedObjectFiles));

  if (mSymbolObjectFilePath) {
    it = fmt::format_to(it, R"(,"symbolFilePath":"{}")", *mSymbolObjectFilePath);
  }

  it = fmt::format_to(it, R"(,"addressRange":"{}:{}"}}}}}})", mAddressRange.low, mAddressRange.high);

  return result;
}

ContinuedEvent::ContinuedEvent(Pid pid, Tid tid, bool allThreads) noexcept
    : UIResult{pid}, mThreadId(tid), mAllThreadsContinued(allThreads)
{
}

std::pmr::string
ContinuedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(
    R"({{"seq":{},"processId":{},"type":"event","event":"continued","body":{{"threadId":{},"allThreadsContinued":{}}}}})",
    seq, mPid, mThreadId, mAllThreadsContinued);
}

Process::Process(Pid parentPid, Pid pid, std::string name, bool isLocal) noexcept
    : UIResult{parentPid}, mName(std::move(name)), mProcessId(pid), mIsLocal(isLocal)
{
}

std::pmr::string
CustomEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(R"({{"seq":{},"processId":{},"type":"event","event":"{}","body":{}}})", seq, mPid,
                  mCustomEventName, mSerializedBody);
}

std::pmr::string
Process::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(
    R"({{"seq":{},"processId":{},"type":"event","event":"process","body":{{"name":"{}","isLocalProcess":true,"startMethod":"attach","processId":{}}}}})",
    seq, mPid, mName, mProcessId);
}

ExitedEvent::ExitedEvent(Pid pid, int exitCode) noexcept : UIResult{pid}, mExitCode(exitCode) {}
std::pmr::string
ExitedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(R"({{"seq":{},"processId":{},"type":"event","event":"exited","body":{{"exitCode":{}}}}})", seq,
                  mPid, mExitCode);
}

ThreadEvent::ThreadEvent(Pid pid, ThreadReason reason, Tid tid) noexcept
    : UIResult{pid}, mReason(reason), mTid(tid)
{
}
ThreadEvent::ThreadEvent(Pid pid, const Clone &event) noexcept
    : UIResult{pid}, mReason(ThreadReason::Started), mTid(event.mChildTid)
{
}

std::pmr::string
ThreadEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(
    R"({{"seq":{},"processId":{},"type":"event","event":"thread","body":{{"reason":"{}","threadId":{}}}}})", seq,
    mPid, to_str(mReason), mTid);
}

StoppedEvent::StoppedEvent(Pid pid, StoppedReason reason, std::string_view description, Tid tid,
                           std::vector<int> breakpointIds, std::string_view text, bool allStopped) noexcept
    : UIResult{pid}, mReason(reason), mDescription(description), mTid(tid),
      mBreakpointIds(std::move(breakpointIds)), mText(text), mAllThreadsStopped(allStopped)
{
}

std::pmr::string
StoppedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  nlohmann::json ensure_desc_utf8 = mDescription;
  const auto descriptionUtf8 = ensure_desc_utf8.dump();
  if (mText.empty()) {
    ReturnFormatted(
      R"({{"seq":{},"processId":{},"type":"event","event":"stopped","body":{{"reason":"{}","threadId":{},"description":{},"text":"","allThreadsStopped":{},"hitBreakpointIds":[{}]}}}})",
      seq, mPid, to_str(mReason), mTid, descriptionUtf8, mAllThreadsStopped, fmt::join(mBreakpointIds, ","));
  } else {
    const nlohmann::json ensure_utf8 = mText;
    const auto utf8text = ensure_utf8.dump();
    ReturnFormatted(
      R"({{"seq":{},"processId":{},"type":"event","event":"stopped","body":{{ "reason":"{}","threadId":{},"description":{},"text":{},"allThreadsStopped":{},"hitBreakpointIds":[{}]}}}})",
      seq, mPid, to_str(mReason), mTid, descriptionUtf8, utf8text, mAllThreadsStopped,
      fmt::join(mBreakpointIds, ","));
  }
}

BreakpointEvent::BreakpointEvent(Pid pid, std::string_view reason, std::optional<std::string> message,
                                 const UserBreakpoint *breakpoint) noexcept
    : UIResult{pid}, mReason(reason), mMessage(std::move(message)), mBreakpoint(breakpoint)
{
}

template <typename T, typename Fn, typename... Optionals>
std::optional<T>
zip(Fn &&fn, Optionals... opts) noexcept
{
  if ((opts && ...)) {
    return fn(opts.value()...);
  } else {
    return std::optional<T>{};
  }
}

std::pmr::string
BreakpointEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{arenaAllocator};
  result.reserve(1024);
  auto it = std::back_inserter(result);
  it = fmt::format_to(
    it,
    R"({{"seq":{},"processId":{},"type":"event","event":"breakpoint","body":{{"reason":"{}","breakpoint":{{"id":{},"verified":{})",
    seq, mPid, mReason, mBreakpoint->mId, mBreakpoint->IsVerified());

  if (mMessage) {
    it = fmt::format_to(it, R"(,"message": "{}")", mMessage.value());
  }
  if (auto src = mBreakpoint->GetSourceFile(); src) {
    it = fmt::format_to(it, R"(,"source": {{"name":"{}", "path": "{}"}})", src.value(), src.value());
  }
  if (const auto line = mBreakpoint->Line(); line) {
    it = fmt::format_to(it, R"(,"line":{})", line.value());
  }
  if (const auto col = mBreakpoint->Column(); col) {
    it = fmt::format_to(it, R"(,"column":{})", col.value());
  }
  if (auto addr = mBreakpoint->Address(); addr) {
    it = fmt::format_to(it, R"(,"instructionReference": "{}")", addr.value());
  }

  it = fmt::format_to(it, "}}}}}}");
  return result;
}

OutputEvent::OutputEvent(Pid pid, std::string_view category, std::string &&output) noexcept
    : UIResult{pid}, mCategory(category), mOutput(std::move(output))
{
}

std::pmr::string
OutputEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  nlohmann::json escape_hack;
  escape_hack = mOutput;
  const auto body = escape_hack.dump();
  std::pmr::string result{arenaAllocator};
  fmt::format_to(
    std::back_inserter(result),
    R"({{"seq":{},"processId":{},"type":"event","event":"output","body":{{"category":"{}","output":{}}}}})", seq,
    mPid, mCategory, body);
  return result;
}
} // namespace mdb::ui::dap

#undef ReturnFormatted