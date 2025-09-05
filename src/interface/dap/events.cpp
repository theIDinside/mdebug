/** LICENSE TEMPLATE */
#include "events.h"
#include <event_queue.h>
#include <symbolication/objfile.h>
#include <utils/format_utils.h>

namespace mdb::ui::dap {
#define ReturnFormatted(formatString, ...)                                                                        \
  std::pmr::string result{ arenaAllocator };                                                                      \
  std::format_to(std::back_inserter(result), formatString __VA_OPT__(, ) __VA_ARGS__);                            \
  return result
// std::pmr::string Serialize(int monotonic_id, std::pmr::memory_resource* allocator=nullptr) const noexcept final;
std::pmr::string
InitializedEvent::Serialize(int, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  // In cases where we attach to an existing process, the client (vscode+extension) can get the sessionId <=>
  // process id mapping immediately For Launch requests however, we can't create this mapping until the process is
  // actually created, post spawn. It's up to the client to create this mapping based on what kind of request it's
  // starting with.
  if (mProcessId) {
    ReturnFormatted(
      R"({{"seq":{},"sessionId":{},"type":"event","event":"initialized", "body":{{"sessionId":{}, "processId":{}}}}})",
      1,
      mSessionId,
      mSessionId,
      *mProcessId);
  } else {
    ReturnFormatted(
      R"({{"seq":{},"sessionId":{},"type":"event","event":"initialized", "body":{{"sessionId":{}, "processId":null}}}})",
      1,
      mSessionId,
      mSessionId);
  }
}

std::pmr::string
TerminatedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(R"({{"seq":{},"sessionId":{},"type":"event", "event":"terminated" }})", seq, mSessionId);
}

ModuleEvent::ModuleEvent(SessionId sessionId,
  std::string_view id,
  std::string_view reason,
  std::string &&name,
  Path &&path,
  std::optional<std::string> &&symbolFilePath,
  std::optional<std::string> &&version,
  AddressRange range,
  SharedObjectSymbols sharedObjects) noexcept
    : UIResult(sessionId), mObjectFileId(id), mReason(reason), mName(std::move(name)), mPath(std::move(path)),
      mAddressRange(range), mSharedObjectFiles(sharedObjects), mSymbolObjectFilePath(std::move(symbolFilePath)),
      version(std::move(version))
{
}

ModuleEvent::ModuleEvent(SessionId sessionId, std::string_view reason, const ObjectFile &object_file) noexcept
    : UIResult(sessionId), mObjectFileId(object_file.GetObjectFileId()), mReason(reason),
      mName(object_file.GetFilePath().filename()), mPath(object_file.GetFilePath()),
      mAddressRange(object_file.GetAddressRange()), mSharedObjectFiles(SharedObjectSymbols::None),
      mSymbolObjectFilePath(object_file.GetFilePath()), version()
{
}

ModuleEvent::ModuleEvent(SessionId sessionId, std::string_view reason, const SymbolFile &symbol_file) noexcept
    : UIResult(sessionId), mObjectFileId(symbol_file.mSymbolObjectFileId), mReason(reason),
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
    return opt.transform([](auto &value) { return std::format(R"("{}")", value); }).value_or("null");
  } else {
    return opt.transform([](auto &value) { return std::format(R"({})", value); }).value_or("null");
  }
}

std::pmr::string
ModuleEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{ arenaAllocator };

  auto it = std::format_to(std::back_inserter(result),
    R"({{"seq":{},"sessionId":{},"type":"event","event":"module","body":{{"reason":"{}", "module":{{"id":"{}","name":"{}","path":"{}")",
    seq,
    mSessionId,
    mReason,
    mObjectFileId,
    mName,
    mPath.c_str());

  if (version) {
    it = std::format_to(it, R"(,"version":"{}")", *version);
  }
  it = std::format_to(it, R"(,"symbolStatus":"{}")", SharedObjectSymbolInfo(mSharedObjectFiles));

  if (mSymbolObjectFilePath) {
    it = std::format_to(it, R"(,"symbolFilePath":"{}")", *mSymbolObjectFilePath);
  }

  it = std::format_to(it, R"(,"addressRange":"{}:{}"}}}}}})", mAddressRange.low, mAddressRange.high);

  return result;
}

ContinuedEvent::ContinuedEvent(SessionId sessionId, Tid tid, bool allThreads) noexcept
    : UIResult{ sessionId }, mThreadId(tid), mAllThreadsContinued(allThreads)
{
}

std::pmr::string
ContinuedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(
    R"({{"seq":{},"sessionId":{},"type":"event","event":"continued","body":{{"threadId":{},"allThreadsContinued":{}}}}})",
    seq,
    mSessionId,
    mThreadId,
    mAllThreadsContinued);
}

Process::Process(SessionId parentSessionId, SessionId pid, std::string name, bool isLocal) noexcept
    : UIResult{ parentSessionId }, mName(std::move(name)), mProcessId(pid), mIsLocal(isLocal)
{
}

std::pmr::string
CustomEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(R"({{"seq":{},"sessionId":{},"type":"event","event":"{}","body":{}}})",
    seq,
    mSessionId,
    mCustomEventName,
    mSerializedBody);
}

std::pmr::string
Process::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(
    R"({{"seq":{},"sessionId":{},"type":"event","event":"process","body":{{"name":"{}","isLocalProcess":true,"startMethod":"attach","processId":{}}}}})",
    seq,
    mSessionId,
    mName,
    mProcessId);
}

ExitedEvent::ExitedEvent(SessionId sessionId, int exitCode) noexcept : UIResult{ sessionId }, mExitCode(exitCode)
{
}

std::pmr::string
ExitedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(R"({{"seq":{},"sessionId":{},"type":"event","event":"exited","body":{{"exitCode":{}}}}})",
    seq,
    mSessionId,
    mExitCode);
}

ThreadEvent::ThreadEvent(SessionId sessionId, ThreadReason reason, Tid tid) noexcept
    : UIResult{ sessionId }, mReason(reason), mTid(tid)
{
}

ThreadEvent::ThreadEvent(SessionId sessionId, const Clone &event) noexcept
    : UIResult{ sessionId }, mReason(ThreadReason::Started), mTid(event.mChildTid)
{
}

std::pmr::string
ThreadEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(
    R"({{"seq":{},"sessionId":{},"type":"event","event":"thread","body":{{"reason":"{}","threadId":{}}}}})",
    seq,
    mSessionId,
    to_str(mReason),
    mTid);
}

StoppedEvent::StoppedEvent(SessionId sessionId,
  StoppedReason reason,
  std::string_view description,
  Tid tid,
  std::vector<int> breakpointIds,
  std::string_view text,
  bool allStopped) noexcept
    : UIResult{ sessionId }, mReason(reason), mDescription(description), mTid(tid),
      mBreakpointIds(std::move(breakpointIds)), mText(text), mAllThreadsStopped(allStopped)
{
}

std::pmr::string
StoppedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  if (mText.empty()) {
    ReturnFormatted(
      R"({{"seq":{},"sessionId":{},"type":"event","event":"stopped","body":{{"reason":"{}","threadId":{},"description":"{}","text":"","allThreadsStopped":{},"hitBreakpointIds":[{}]}}}})",
      seq,
      mSessionId,
      to_str(mReason),
      mTid,
      mDescription,
      mAllThreadsStopped,
      JoinFormatIterator{ mBreakpointIds, "," });
  } else {
    ReturnFormatted(
      R"({{"seq":{},"sessionId":{},"type":"event","event":"stopped","body":{{ "reason":"{}","threadId":{},"description":"{}","text":"{}","allThreadsStopped":{},"hitBreakpointIds":[{}]}}}})",
      seq,
      mSessionId,
      to_str(mReason),
      mTid,
      mDescription,
      mText,
      mAllThreadsStopped,
      JoinFormatIterator{ mBreakpointIds, "," });
  }
}

BreakpointEvent::BreakpointEvent(SessionId sessionId,
  std::string_view reason,
  std::optional<std::string> message,
  const UserBreakpoint *breakpoint) noexcept
    : UIResult{ sessionId }, mReason(reason), mMessage(std::move(message)), mBreakpoint(breakpoint)
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
  std::pmr::string result{ arenaAllocator };
  result.reserve(1024);
  auto it = std::back_inserter(result);
  it = std::format_to(it,
    R"({{"seq":{},"sessionId":{},"type":"event","event":"breakpoint","body":{{"reason":"{}","breakpoint":{{"id":{},"verified":{})",
    seq,
    mSessionId,
    mReason,
    mBreakpoint->mId,
    mBreakpoint->IsVerified());

  if (mMessage) {
    it = std::format_to(it, R"(,"message": "{}")", mMessage.value());
  }
  if (auto src = mBreakpoint->GetSourceFile(); src) {
    it = std::format_to(it, R"(,"source": {{"name":"{}", "path": "{}"}})", src.value(), src.value());
  }
  if (const auto line = mBreakpoint->Line(); line) {
    it = std::format_to(it, R"(,"line":{})", line.value());
  }
  if (const auto col = mBreakpoint->Column(); col) {
    it = std::format_to(it, R"(,"column":{})", col.value());
  }
  if (auto addr = mBreakpoint->Address(); addr) {
    it = std::format_to(it, R"(,"instructionReference": "{}")", addr.value());
  }

  it = std::format_to(it, "}}}}}}");
  return result;
}

OutputEvent::OutputEvent(SessionId pid, std::string_view category, std::string &&output) noexcept
    : UIResult{ pid }, mCategory(category), mOutput(std::move(output))
{
}

std::pmr::string
OutputEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  std::pmr::string result{ arenaAllocator };
  std::format_to(std::back_inserter(result),
    R"({{"seq":{},"sessionId":{},"type":"event","event":"output","body":{{"category":"{}","output":"{}"}}}})",
    seq,
    mSessionId,
    mCategory,
    EscapeFormatter{ mOutput });
  return result;
}
} // namespace mdb::ui::dap

#undef ReturnFormatted