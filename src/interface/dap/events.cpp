/** LICENSE TEMPLATE */
#include "events.h"
#include "fmt/core.h"
#include "fmt/format.h"
#include "fmt/ranges.h"
#include "interface/dap/dap_defs.h"
#include "interface/dap/types.h"
#include "nlohmann/json.hpp"
#include <event_queue.h>
#include <so_loading.h>
#include <symbolication/objfile.h>

namespace ui::dap {
#define ReturnFormatted(formatString, ...)                                                                        \
  std::pmr::string result{arenaAllocator};                                                                        \
  fmt::format_to(std::back_inserter(result), formatString __VA_OPT__(, ) __VA_ARGS__);                            \
  return result
// std::pmr::string Serialize(int monotonic_id, std::pmr::memory_resource* allocator=nullptr) const noexcept final;
std::pmr::string
InitializedEvent::Serialize(int, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(R"({{"seq":{}, "type":"event", "event":"initialized" }})", 1);
}

std::pmr::string
TerminatedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(R"({{"seq":{}, "type":"event", "event":"terminated" }})", seq);
}

ModuleEvent::ModuleEvent(std::string_view id, std::string_view reason, std::string &&name, Path &&path,
                         std::optional<std::string> &&symbol_file_path, std::optional<std::string> &&version,
                         AddressRange range, SharedObjectSymbols so_sym_info) noexcept
    : objfile_id(id), reason(reason), name(std::move(name)), path(std::move(path)), addr_range(range),
      sym_info(so_sym_info), symbol_file_path(std::move(symbol_file_path)), version(std::move(version))
{
}

ModuleEvent::ModuleEvent(std::string_view reason, const SharedObject &so) noexcept
    : objfile_id(so.objfile->GetObjectFileId()), reason(reason), name(so.name()), path(so.path),
      addr_range(so.relocated_addr_range()), sym_info(so.symbol_info), symbol_file_path(so.symbol_file_path()),
      version(so.version())
{
}

ModuleEvent::ModuleEvent(std::string_view reason, const ObjectFile &object_file) noexcept
    : objfile_id(object_file.GetObjectFileId()), reason(reason), name(object_file.GetFilePath().filename()),
      path(object_file.GetFilePath()), addr_range(object_file.GetAddressRange()),
      sym_info(SharedObjectSymbols::None), symbol_file_path(object_file.GetFilePath()), version()
{
}

ModuleEvent::ModuleEvent(std::string_view reason, const SymbolFile &symbol_file) noexcept
    : objfile_id(symbol_file.mSymbolObjectFileId), reason(reason),
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
    R"({{"seq":{},"type":"event","event":"module","body":{{"reason":"{}", "module":{{"id":"{}","name":"{}","path":"{}")",
    seq, reason, objfile_id, name, path.c_str());

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

ContinuedEvent::ContinuedEvent(Tid tid, bool all_threads) noexcept
    : thread_id(tid), all_threads_continued(all_threads)
{
}

std::pmr::string
ContinuedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(
    R"({{"seq":{}, "type":"event", "event":"continued", "body":{{"threadId":{}, "allThreadsContinued":{}}}}})",
    seq, thread_id, all_threads_continued);
}

Process::Process(std::string name, bool is_local) noexcept : name(std::move(name)), is_local(is_local) {}

std::pmr::string
Process::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(
    R"({{"seq":{}, "type":"event", "event":"process", "body":{{"name":"{}", "isLocalProcess": true, "startMethod": "attach" }}}})",
    seq, name);
}

ExitedEvent::ExitedEvent(int exit_code) noexcept : exit_code(exit_code) {}
std::pmr::string
ExitedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(R"({{"seq":{}, "type":"event", "event":"exited", "body":{{"exitCode":{}}}}})", seq, exit_code);
}

ThreadEvent::ThreadEvent(ThreadReason reason, Tid tid) noexcept : reason(reason), tid(tid) {}
ThreadEvent::ThreadEvent(const Clone &event) noexcept : reason(ThreadReason::Started), tid(event.child_tid) {}

std::pmr::string
ThreadEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  ReturnFormatted(R"({{"seq":{}, "type":"event", "event":"thread", "body":{{"reason":"{}", "threadId":{}}}}})",
                  seq, to_str(reason), tid);
}

StoppedEvent::StoppedEvent(StoppedReason reason, std::string_view description, Tid tid, std::vector<int> bps,
                           std::string_view text, bool all_stopped) noexcept
    : reason(reason), description(description), tid(tid), bp_ids(bps), text(text), all_threads_stopped(all_stopped)
{
}

std::pmr::string
StoppedEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  nlohmann::json ensure_desc_utf8 = description;
  const auto description_utf8 = ensure_desc_utf8.dump();
  if (text.empty()) {
    ReturnFormatted(
      R"({{"seq":{}, "type":"event", "event":"stopped", "body":{{ "reason":"{}", "threadId":{}, "description": {}, "text": "", "allThreadsStopped": {}, "hitBreakpointIds": [{}]}}}})",
      seq, to_str(reason), tid, description_utf8, all_threads_stopped, fmt::join(bp_ids, ","));
  } else {
    const nlohmann::json ensure_utf8 = text;
    const auto utf8text = ensure_utf8.dump();
    ReturnFormatted(
      R"({{"seq":{}, "type":"event", "event":"stopped", "body":{{ "reason":"{}", "threadId":{}, "description": {}, "text": {}, "allThreadsStopped": {}, "hitBreakpointIds": [{}]}}}})",
      seq, to_str(reason), tid, description_utf8, utf8text, all_threads_stopped, fmt::join(bp_ids, ","));
  }
}

BreakpointEvent::BreakpointEvent(std::string_view reason, std::optional<std::string> message,
                                 const UserBreakpoint *breakpoint) noexcept
    : reason(reason), message(std::move(message)), breakpoint(breakpoint)
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
    R"({{"seq":{},"type":"event","event":"breakpoint","body":{{"reason":"{}","breakpoint":{{"id":{},"verified":{})",
    seq, reason, breakpoint->id, breakpoint->verified());

  if (message) {
    it = fmt::format_to(it, R"(,"message": "{}")", message.value());
  }
  if (auto src = breakpoint->source_file(); src) {
    it = fmt::format_to(it, R"(,"source": {{"name":"{}", "path": "{}"}})", src.value(), src.value());
  }
  if (const auto line = breakpoint->line(); line) {
    it = fmt::format_to(it, R"(,"line":{})", line.value());
  }
  if (const auto col = breakpoint->column(); col) {
    it = fmt::format_to(it, R"(,"column":{})", col.value());
  }
  if (auto addr = breakpoint->address(); addr) {
    it = fmt::format_to(it, R"(,"instructionReference": "{}")", addr.value());
  }

  it = fmt::format_to(it, "}}}}}}");
  return result;
}

OutputEvent::OutputEvent(std::string_view category, std::string &&output) noexcept
    : category(category), output(std::move(output))
{
}

std::pmr::string
OutputEvent::Serialize(int seq, std::pmr::memory_resource *arenaAllocator) const noexcept
{
  nlohmann::json escape_hack;
  escape_hack = output;
  const auto body = escape_hack.dump();
  std::pmr::string result{arenaAllocator};
  fmt::format_to(std::back_inserter(result),
                 R"({{"seq":{}, "type":"event", "event":"output", "body":{{"category":"{}", "output":{}}}}})", seq,
                 category, body);
  return result;
}
} // namespace ui::dap

#undef ReturnFormatted