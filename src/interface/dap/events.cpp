#include "events.h"
#include "fmt/core.h"
#include "fmt/format.h"
#include "fmt/ranges.h"
#include "interface/dap/types.h"
#include "nlohmann/json.hpp"
#include <so_loading.h>
#include <symbolication/objfile.h>

namespace ui::dap {

std::string
InitializedEvent::serialize(int) const noexcept
{
  return fmt::format(R"({{"seq":{}, "type":"event", "event":"initialized" }})", 1);
}

std::string
TerminatedEvent::serialize(int seq) const noexcept
{
  return fmt::format(R"({{"seq":{}, "type":"event", "event":"terminated" }})", seq);
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
    : objfile_id(symbol_file.symbolFileId()), reason(reason), name(symbol_file.path().filename()),
      path(symbol_file.path()), addr_range(symbol_file.pc_bounds), sym_info(SharedObjectSymbols::Full),
      symbol_file_path(symbol_file.path().c_str()), version()
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

std::string
ModuleEvent::serialize(int seq) const noexcept
{
  auto out = fmt::memory_buffer();
  constexpr auto bi = [](auto &out) { return std::back_inserter(out); };
  fmt::format_to(
    bi(out),
    R"({{"seq":{},"type":"event","event":"module","body":{{"reason":"{}", "module":{{"id":"{}","name":"{}","path":"{}")",
    seq, reason, objfile_id, name, path.c_str());

  if (version) {
    fmt::format_to(bi(out), R"(,"version":"{}")", *version);
  }
  fmt::format_to(bi(out), R"(,"symbolStatus":"{}")", so_sym_info_description(sym_info));

  if (symbol_file_path) {
    fmt::format_to(bi(out), R"(,"symbolFilePath":"{}")", *symbol_file_path);
  }

  fmt::format_to(bi(out), R"(,"addressRange":"{}:{}"}}}}}})", addr_range.low, addr_range.high);

  return fmt::to_string(out);
}

ContinuedEvent::ContinuedEvent(Tid tid, bool all_threads) noexcept
    : thread_id(tid), all_threads_continued(all_threads)
{
}

std::string
ContinuedEvent::serialize(int seq) const noexcept
{
  return fmt::format(
    R"({{"seq":{}, "type":"event", "event":"continued", "body":{{"threadId":{}, "allThreadsContinued":{}}}}})",
    seq, thread_id, all_threads_continued);
}

Process::Process(std::string name, bool is_local) noexcept : name(std::move(name)), is_local(is_local) {}

std::string
Process::serialize(int seq) const noexcept
{
  return fmt::format(
    R"({{"seq":{}, "type":"event", "event":"process", "body":{{"name":"{}", "isLocalProcess": true, "startMethod": "attach" }}}})",
    seq, name);
}

ExitedEvent::ExitedEvent(int exit_code) noexcept : exit_code(exit_code) {}
std::string
ExitedEvent::serialize(int seq) const noexcept
{
  return fmt::format(R"({{"seq":{}, "type":"event", "event":"exited", "body":{{"exitCode":{}}}}})", seq,
                     exit_code);
}

ThreadEvent::ThreadEvent(ThreadReason reason, Tid tid) noexcept : reason(reason), tid(tid) {}

std::string
ThreadEvent::serialize(int seq) const noexcept
{
  return fmt::format(R"({{"seq":{}, "type":"event", "event":"thread", "body":{{"reason":"{}", "threadId":{}}}}})",
                     seq, to_str(reason), tid);
}

StoppedEvent::StoppedEvent(StoppedReason reason, std::string_view description, Tid tid, std::vector<int> bps,
                           std::string_view text, bool all_stopped) noexcept
    : reason(reason), description(description), tid(tid), bp_ids(bps), text(text), all_threads_stopped(all_stopped)
{
}

std::string
StoppedEvent::serialize(int seq) const noexcept
{
  nlohmann::json ensure_desc_utf8 = description;
  const auto description_utf8 = ensure_desc_utf8.dump();
  if (text.empty()) {
    return fmt::format(
      R"({{"seq":{}, "type":"event", "event":"stopped", "body":{{ "reason":"{}", "threadId":{}, "description": {}, "text": "", "allThreadsStopped": {}, "hitBreakpointIds": [{}]}}}})",
      seq, to_str(reason), tid, description_utf8, all_threads_stopped, fmt::join(bp_ids, ","));
  } else {
    const nlohmann::json ensure_utf8 = text;
    const auto utf8text = ensure_utf8.dump();
    return fmt::format(
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

std::string
BreakpointEvent::serialize(int seq) const noexcept
{

  std::string result{};
  result.reserve(256);
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

std::string
OutputEvent::serialize(int seq) const noexcept
{
  nlohmann::json escape_hack;
  escape_hack = output;
  const auto body = escape_hack.dump();
  return fmt::format(R"({{"seq":{}, "type":"event", "event":"output", "body":{{"category":"{}", "output":{}}}}})",
                     seq, category, body);
}
} // namespace ui::dap