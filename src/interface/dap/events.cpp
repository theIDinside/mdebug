#include "events.h"
#include "../../so_loading.h"
#include "fmt/format.h"
#include "nlohmann/json.hpp"

namespace ui::dap {

ModuleEvent::ModuleEvent(int id, std::string_view reason, std::string &&name, Path &&path,
                         std::optional<std::string> &&symbol_file_path, std::optional<std::string> &&version,
                         AddressRange range, SharedObjectSymbols so_sym_info) noexcept
    : id(id), reason(reason), name(std::move(name)), path(std::move(path)), addr_range(range),
      sym_info(so_sym_info), symbol_file_path(std::move(symbol_file_path)), version(std::move(version))
{
}

ModuleEvent::ModuleEvent(std::string_view reason, const SharedObject &so) noexcept
    : id(so.so_id), reason(reason), name(so.name()), path(so.path), addr_range(so.relocated_addr_range()),
      sym_info(so.symbol_info), symbol_file_path(so.symbol_file_path()), version(so.version())
{
}

std::string
ModuleEvent::serialize(int seq) const noexcept
{
  auto out = fmt::memory_buffer();
  constexpr auto bi = [](auto &out) { return std::back_inserter(out); };
  fmt::format_to(
      bi(out),
      R"({{"seq":{},"type":"event","event":"module","body":{{"reason":"{}", "module":{{"id":{},"name":"{}","path":"{}")",
      seq, reason, id, name, path.c_str());

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

std::string
BreakpointEvent::serialize(int) const noexcept
{
  TODO("unimplemented");
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