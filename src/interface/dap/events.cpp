/** LICENSE TEMPLATE */
#include "events.h"
#include "fmt/core.h"
#include "fmt/format.h"
#include "fmt/ranges.h"
#include "nlohmann/json.hpp"
#include <event_queue.h>
#include <so_loading.h>
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
                         std::optional<std::string> &&symbol_file_path, std::optional<std::string> &&version,
                         AddressRange range, SharedObjectSymbols so_sym_info) noexcept
    : UIResult(pid), objfile_id(id), reason(reason), name(std::move(name)), path(std::move(path)),
      addr_range(range), sym_info(so_sym_info), symbol_file_path(std::move(symbol_file_path)),
      version(std::move(version))
{
}

ModuleEvent::ModuleEvent(Pid pid, std::string_view reason, const SharedObject &so) noexcept
    : UIResult(pid), objfile_id(so.objfile->GetObjectFileId()), reason(reason), name(so.name()), path(so.path),
      addr_range(so.relocated_addr_range()), sym_info(so.symbol_info), symbol_file_path(so.symbol_file_path()),
      version(so.version())
{
}

ModuleEvent::ModuleEvent(Pid pid, std::string_view reason, const ObjectFile &object_file) noexcept
    : UIResult(pid), objfile_id(object_file.GetObjectFileId()), reason(reason),
      name(object_file.GetFilePath().filename()), path(object_file.GetFilePath()),
      addr_range(object_file.GetAddressRange()), sym_info(SharedObjectSymbols::None),
      symbol_file_path(object_file.GetFilePath()), version()
{
}

ModuleEvent::ModuleEvent(Pid pid, std::string_view reason, const SymbolFile &symbol_file) noexcept
    : UIResult(pid), objfile_id(symbol_file.mSymbolObjectFileId), reason(reason),
      name(symbol_file.GetObjectFilePath().filename()), path(symbol_file.GetObjectFilePath()),
      addr_range(symbol_file.mPcBounds), sym_info(SharedObjectSymbols::Full),
      symbol_file_path(symbol_file.GetObjectFilePath().c_str()), version()
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
    seq, mPid, reason, objfile_id, name, path.c_str());

  if (version) {
    it = fmt::format_to(it, R"(,"version":"{}")", *version);
  }
  it = fmt::format_to(it, R"(,"symbolStatus":"{}")", so_sym_info_description(sym_info));

  if (symbol_file_path) {
    it = fmt::format_to(it, R"(,"symbolFilePath":"{}")", *symbol_file_path);
  }

  it = fmt::format_to(it, R"(,"addressRange":"{}:{}"}}}}}})", addr_range.low, addr_range.high);

  return result;
}

ContinuedEvent::ContinuedEvent(Pid pid, Tid tid, bool all_threads) noexcept
    : UIResult{pid}, thread_id(tid), all_threads_continued(all_threads)
{
}

std::pmr::string
ContinuedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(
    R"({{"seq":{},"processId":{},"type":"event","event":"continued","body":{{"threadId":{},"allThreadsContinued":{}}}}})",
    seq, mPid, thread_id, all_threads_continued);
}

Process::Process(Pid parentPid, Pid pid, std::string name, bool is_local) noexcept
    : UIResult{parentPid}, name(std::move(name)), mProcessId(pid), is_local(is_local)
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
    seq, mPid, name, mProcessId);
}

ExitedEvent::ExitedEvent(Pid pid, int exit_code) noexcept : UIResult{pid}, exit_code(exit_code) {}
std::pmr::string
ExitedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(R"({{"seq":{},"processId":{},"type":"event","event":"exited","body":{{"exitCode":{}}}}})", seq,
                  mPid, exit_code);
}

ThreadEvent::ThreadEvent(Pid pid, ThreadReason reason, Tid tid) noexcept : UIResult{pid}, reason(reason), tid(tid)
{
}
ThreadEvent::ThreadEvent(Pid pid, const Clone &event) noexcept
    : UIResult{pid}, reason(ThreadReason::Started), tid(event.child_tid)
{
}

std::pmr::string
ThreadEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(
    R"({{"seq":{},"processId":{},"type":"event","event":"thread","body":{{"reason":"{}","threadId":{}}}}})", seq,
    mPid, to_str(reason), tid);
}

StoppedEvent::StoppedEvent(Pid pid, StoppedReason reason, std::string_view description, Tid tid,
                           std::vector<int> bps, std::string_view text, bool all_stopped) noexcept
    : UIResult{pid}, reason(reason), description(description), tid(tid), bp_ids(bps), text(text),
      all_threads_stopped(all_stopped)
{
}

std::pmr::string
StoppedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  nlohmann::json ensure_desc_utf8 = description;
  const auto description_utf8 = ensure_desc_utf8.dump();
  if (text.empty()) {
    ReturnFormatted(
      R"({{"seq":{},"processId":{},"type":"event","event":"stopped","body":{{"reason":"{}","threadId":{},"description":{},"text":"","allThreadsStopped":{},"hitBreakpointIds":[{}]}}}})",
      seq, mPid, to_str(reason), tid, description_utf8, all_threads_stopped, fmt::join(bp_ids, ","));
  } else {
    const nlohmann::json ensure_utf8 = text;
    const auto utf8text = ensure_utf8.dump();
    ReturnFormatted(
      R"({{"seq":{},"processId":{},"type":"event","event":"stopped","body":{{ "reason":"{}","threadId":{},"description":{},"text":{},"allThreadsStopped":{},"hitBreakpointIds":[{}]}}}})",
      seq, mPid, to_str(reason), tid, description_utf8, utf8text, all_threads_stopped, fmt::join(bp_ids, ","));
  }
}

BreakpointEvent::BreakpointEvent(Pid pid, std::string_view reason, std::optional<std::string> message,
                                 const UserBreakpoint *breakpoint) noexcept
    : UIResult{pid}, reason(reason), message(std::move(message)), breakpoint(breakpoint)
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
    seq, mPid, reason, breakpoint->mId, breakpoint->IsVerified());

  if (message) {
    it = fmt::format_to(it, R"(,"message": "{}")", message.value());
  }
  if (auto src = breakpoint->GetSourceFile(); src) {
    it = fmt::format_to(it, R"(,"source": {{"name":"{}", "path": "{}"}})", src.value(), src.value());
  }
  if (const auto line = breakpoint->Line(); line) {
    it = fmt::format_to(it, R"(,"line":{})", line.value());
  }
  if (const auto col = breakpoint->Column(); col) {
    it = fmt::format_to(it, R"(,"column":{})", col.value());
  }
  if (auto addr = breakpoint->Address(); addr) {
    it = fmt::format_to(it, R"(,"instructionReference": "{}")", addr.value());
  }

  it = fmt::format_to(it, "}}}}}}");
  return result;
}

OutputEvent::OutputEvent(Pid pid, std::string_view category, std::string &&output) noexcept
    : UIResult{pid}, category(category), output(std::move(output))
{
}

std::pmr::string
OutputEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  nlohmann::json escape_hack;
  escape_hack = output;
  const auto body = escape_hack.dump();
  std::pmr::string result{arenaAllocator};
  fmt::format_to(
    std::back_inserter(result),
    R"({{"seq":{},"processId":{},"type":"event","event":"output","body":{{"category":"{}","output":{}}}}})", seq,
    mPid, category, body);
  return result;
}
} // namespace mdb::ui::dap

#undef ReturnFormatted