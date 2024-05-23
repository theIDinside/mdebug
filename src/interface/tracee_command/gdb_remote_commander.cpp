#include "gdb_remote_commander.h"
#include "common.h"
#include "fmt/core.h"
#include "interface/remotegdb/shared.h"
#include "interface/remotegdb/target_description.h"
#include "interface/tracee_command/tracee_command_interface.h"
// #include "symbolication/dwarf_binary_reader.h"
#include "task.h"
#include "utils/logger.h"
#include "utils/util.h"
#include "utils/xml.h"
#include <array>
#include <charconv>
#include <chrono>
#include <tracer.h>

namespace tc {

template <typename T, typename U> using ViewOfParameter = U;

#define SerializeCommand(Buf, FmtStr, ...)                                                                        \
  [&Buf](auto &&...args) noexcept {                                                                               \
    auto it = fmt::format_to(Buf.begin(), FmtStr, args...);                                                       \
    return std::string_view{Buf.begin(), it};                                                                     \
  }(__VA_ARGS__);

template <size_t N>
static ViewOfParameter<char[], std::string_view>
append_checksum(char (&buf)[N], std::string_view payload)
{
  ASSERT(payload.size() < N, "Alotted buffer of size N={} too small to handle payload's size {}", N,
         payload.size());

  ASSERT(buf[1 + payload.size()] == '#', "Expected a packet end '#' at {} but found {}", 1 + payload.size(),
         buf[1 + payload.size()]);

  auto [a, b] = gdb::checksum(std::string_view{buf + 1, buf + 1 + payload.size()});
  buf[2 + payload.size()] = a;
  buf[3 + payload.size()] = a;
  // Be wary of life time issues here. But I know what I'm doing. The life time of the returned view is bound to
  // the life time of `buf`
  return std::string_view{buf, buf + 3 + payload.size()};
}

GdbRemoteCommander::GdbRemoteCommander(std::shared_ptr<gdb::RemoteConnection> conn, Pid process_id,
                                       std::string &&exec_file,
                                       std::shared_ptr<gdb::ArchictectureInfo> &&arch) noexcept
    : TraceeCommandInterface(TargetFormat::Remote, std::move(arch)), connection(std::move(conn)),
      process_id(process_id), exec_file(std::move(exec_file))
{
}

ReadResult
GdbRemoteCommander::read_bytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept
{
  const auto &settings = connection->settings();
  if (settings.is_non_stop) {
    // we can do reads while running
  } else {
  }
  TODO("Implement");
  (void)address;
  (void)size;
  (void)read_buffer;
}
TraceeWriteResult
GdbRemoteCommander::write_bytes(AddrPtr addr, u8 *buf, u32 size) noexcept
{
  TODO("Implement");
  (void)addr;
  (void)buf;
  (void)size;
}

void
GdbRemoteCommander::set_catch_syscalls(bool on) noexcept
{
  const bool catch_syscall = connection->settings().catch_syscalls;
  if (on && !catch_syscall) {
    const auto response = connection->send_command_with_response("QCatchSyscalls:1", {});
    if (response.is_error()) {
      PANIC("failed to set catch syscalls");
    }
    ASSERT(response.value() == "OK", "Response for command was not 'OK'");
  } else if (!on && catch_syscall) {
    const auto response = connection->send_command_with_response("QCatchSyscalls:0", {});
    if (response.is_error()) {
      PANIC("failed to set catch syscalls");
    }
    ASSERT(response.value() == "OK", "Response for command was not 'OK'");
  }

  connection->settings().catch_syscalls = on;
}

void
GdbRemoteCommander::configure_session() noexcept
{
  // gdb::CommandSerializationBuffer<256> packet_buffer{};
  // const auto extended_mode = connection->send_packet_wait_ack(packet_buffer.write_packet("{}", "!"));
  // ASSERT(extended_mode.was_received(), "Expected to have seen extended request but remote never saw it");

  // const auto op_res = connection->send_packet_wait_ack(packet_buffer.write_packet(
  //     "{}", "qSupported:multiprocess+;swbreak+;hwbreak+;fork-events+;vfork-events+;exec-events+"));

  // ASSERT(op_res.was_received(), "Attempted to send qSupported request but it was never seen");
  // DLOG(LogChannel::remote, "Configuring remote for No Ack Mode");
  // const auto no_ack_res = connection->send_packet(packet_buffer.write_packet("{}", "QStartNoAckMode"));
  // ASSERT(no_ack_res.was_received(), "Attempted to send qSupported request but it was never seen");
}

TaskExecuteResponse
GdbRemoteCommander::resume_task(TaskInfo &t, RunType type) noexcept
{
  set_catch_syscalls(type == RunType::SyscallContinue);

  const auto pid = task_leader();
  std::array<char, 128> buf{};
  std::string_view resume_command;
  switch (type) {
  case RunType::Step: {
    auto it = fmt::format_to(buf.begin(), "vCont;s:p{:x}.{:x}", pid, t.tid);
    resume_command = std::string_view{buf.begin(), it};
  }
  case RunType::Continue:
  case RunType::SyscallContinue:
  case RunType::UNKNOWN: {
    auto it = fmt::format_to(buf.begin(), "vCont;c:p{:x}.{:x}", pid, t.tid);
    resume_command = std::string_view{buf.begin(), it};
  }
  }

  const auto resume_err = connection->send_vcont_command(resume_command, {});
  ASSERT(!resume_err.has_value(), "vCont resume command failed");

  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
GdbRemoteCommander::stop_task(TaskInfo &t) noexcept
{
  gdb::CommandSerializationBuffer<256> packet_buffer{};
  const auto pid = task_leader();
  packet_buffer.write_packet("vCont;t:p{}.{}", pid, t.tid);
  TODO("GdbRemoteCommander::stop_task(TaskInfo &t) noexcept");
}

TaskExecuteResponse
GdbRemoteCommander::enable_breakpoint(BreakpointLocation &location) noexcept
{
  return install_breakpoint(location.address());
}

TaskExecuteResponse
GdbRemoteCommander::disable_breakpoint(BreakpointLocation &location) noexcept
{
  std::array<char, 32> bytes{};
  auto cmd = SerializeCommand(bytes, "z0,{:x},1", location.address().get());
  auto response = connection->send_command_with_response(cmd, 1000);
  if (!(response.is_expected() && response.take_value() == "$OK")) {
    PANIC("Failed to unset breakpoint");
  }
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
GdbRemoteCommander::install_breakpoint(AddrPtr addr) noexcept
{
  std::array<char, 32> bytes{};
  auto cmd = SerializeCommand(bytes, "Z0,{:x},1", addr.get());

  auto res = connection->send_command_with_response(cmd, 1000);
  if (res.is_error()) {
    return TaskExecuteResponse::Error(0);
  }
  if (res.take_value() != "$OK") {
    return TaskExecuteResponse::Error(0);
  }
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
GdbRemoteCommander::read_registers(TaskInfo &t) noexcept
{
  std::array<char, 48> bytes{};
  auto cmd = SerializeCommand(bytes, "Hgp{:x}.{:x}", task_leader(), t.tid);
  auto set_thread = connection->send_command_with_response(cmd, 1000);
  if (set_thread.is_error()) {
    return TaskExecuteResponse::Error(0);
  }
  if (set_thread.take_value() != "$OK") {
    return TaskExecuteResponse::Error(0);
  }

  auto result = connection->send_command_with_response("g", 1000);
  if (result.is_error()) {
    return TaskExecuteResponse::Error(0);
  }

  auto register_contents = result.take_value();
  DBGLOG(core, "Read register field for {}", t.tid);
  RegisterData regs{};

  std::string_view payload{register_contents};
  std::array<char, 2048> normalized{};
  auto dec_length = 0u;

  ASSERT(payload.front() == '$', "Expected OK response");
  payload.remove_prefix(1);
  auto rle_decodings = 0;

  std::vector<u8> decoded{};

  const auto now = std::chrono::high_resolution_clock::now();
  for (auto i = 0u; i < payload.size();) {
    if (payload[i] == '*') {
      const auto repeat_count = static_cast<u32>(payload[i + 1] - char{29});
      std::fill_n(normalized.begin() + dec_length, repeat_count, payload[i - 1]);
      dec_length += repeat_count;
      i += 2;
      ++rle_decodings;
    } else {
      normalized[dec_length++] = payload[i];
      i += 1;
    }
  }
  const auto then = std::chrono::high_resolution_clock::now();
  const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(then - now).count();
  DBGLOG(core, "Decoded RLE {} times in {}ns", rle_decodings, nanos);

  ASSERT(dec_length == arch_info->register_block_size * 2,
         "Expected normalized register data to be x2 of actual register data. Expected: {}, was {}",
         arch_info->register_block_size * 2, dec_length);

  auto byte_pos = 0;
  switch (arch_info->type) {
  case ArchType::X86_64: {
    std::string_view normalized_str{normalized.data(), normalized.data() + dec_length};
    ASSERT(normalized_str.size() % 2 == 0, "Expected string to be divisible by 2");
    while (!normalized_str.empty()) {
      ASSERT(
          std::from_chars(normalized_str.data(), normalized_str.data() + 2, t.regs.x86_block->file[byte_pos], 16)
                  .ec == std::errc(),
          "Failed to convert 2-hex digit format into binary form at position {}", byte_pos);
      byte_pos++;
      normalized_str.remove_prefix(2);
    }
    break;
  }
  case ArchType::COUNT:
    PANIC("ArchType::COUNT not a valid variant");
    break;
  }

  return TaskExecuteResponse::Ok(register_contents.size());
}
TaskExecuteResponse
GdbRemoteCommander::write_registers(const user_regs_struct &input) noexcept
{
  (void)input;
  TODO("Implement");
}
TaskExecuteResponse
GdbRemoteCommander::set_pc(const TaskInfo &t, AddrPtr addr) noexcept
{
  TODO_FMT("Implement set_pc for {} {}", t.tid, addr);
}
TaskExecuteResponse
GdbRemoteCommander::disconnect(bool terminate) noexcept
{
  gdb::CommandSerializationBuffer<4> packet_buffer{};
  packet_buffer.write_packet("{}", "D");
  TODO_FMT("Implement GdbRemoteCommander::disconnect {}", terminate);
}
bool
GdbRemoteCommander::perform_shutdown() noexcept
{
  TODO("Implement");
}

bool
GdbRemoteCommander::initialize() noexcept
{
  connection->initialize_thread();
  return true;
}
bool
GdbRemoteCommander::post_exec(TraceeController *) noexcept
{
  TODO("Implement");
}

std::optional<Path>
GdbRemoteCommander::execed_file() noexcept
{
  if (exec_file) {
    return exec_file.transform([](auto &p) { return Path{p}; });
  } else {
    char buf[10]{0};
    auto ptr = gdb::format_value(buf, process_id);
    gdb::qXferCommand execfile{"qXfer:exec-file:read:", 0x1000, std::string_view{buf, ptr}};
    const auto result = connection->send_qXfer_command_with_response(execfile, 1000);
    if (!result) {
      DBGLOG(core, "Could not retrieve exec file from gdbremote");
    } else {
      TODO_FMT("Convert result from command to Path: {}", execfile.response_buffer);
      return Path{};
    }
  }
  return {};
}

Tid
GdbRemoteCommander::task_leader() const noexcept
{
  return process_id;
}

std::optional<std::vector<ObjectFileDescriptor>>
GdbRemoteCommander::read_libraries() noexcept
{
  TODO("implement GdbRemoteCommander::read_libraries()");
}

std::shared_ptr<gdb::RemoteConnection>
GdbRemoteCommander::remote_connection() noexcept
{
  return connection;
}

utils::Expected<Auxv, Error>
GdbRemoteCommander::read_auxv() noexcept
{
  TODO("GdbRemoteCommander::read_auxv() noexcept");
}

RemoteSessionConfigurator::RemoteSessionConfigurator(gdb::RemoteConnection::ShrPtr remote) noexcept
    : conn(std::move(remote))
{
}

std::vector<std::tuple<Pid, Tid, std::string>>
parse_threads(std::string_view input) noexcept
{
  std::vector<std::tuple<Pid, Tid, std::string>> result{};
  xml::XMLParser parser{input};
  auto root_element = parser.parse();
  result.reserve(root_element->children.size());

  for (const auto &thread : root_element->children) {
    if (const auto lwp = thread->attribute("id"); lwp) {
      std::string_view str = lwp.value();
      const auto [pid, tid] = gdb::parse_thread_id(str);
      result.emplace_back(pid, tid, thread->attribute("name").value_or("None"));
    }
  }
  return result;
}

// Commands that only return OK response, uses this
#define OkOtherwiseErr(cmd, errMsg)                                                                               \
  if (!conn->execute_command(cmd, 5000) || cmd.result.value_or("") != "$OK") {                                    \
    return ConnInitError{.msg = errMsg};                                                                          \
  }

// For use with commands that responds with arbitrary data (i.e. doesn't contain an OK in the string data)
#define SuccessOtherwiseErr(cmd, errMsg)                                                                          \
  if (!conn->execute_command(cmd, 5000)) {                                                                        \
    return ConnInitError{.msg = errMsg};                                                                          \
  }

utils::Expected<std::vector<RemoteProcess>, gdb::ConnInitError>
RemoteSessionConfigurator::configure_session() noexcept
{
  using gdb::ConnInitError, gdb::SocketCommand;
  // Todo; make response buffers in this scope all tied to one allocation instead of multiple

  if (conn->settings().is_noack) {
    SocketCommand noack{"QStartNoAckMode"};
    OkOtherwiseErr(noack, "Failed to configure no ack for connection");
  }
  // TURN ON EXTENDED MODE
  SocketCommand extended{"!"};
  OkOtherwiseErr(extended, "Failed to configure extended mode");

  // INFORM REMOTE OF OUR CAPABILITIES; IT WILL RESPOND WITH THEIRS
  SocketCommand qSupported{
      "qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;"
      "vContSupported+;QThreadEvents+;QThreadOptions+;no-resumed+;memory-tagging+;xmlRegisters=i386;QNonStop+"};
  SuccessOtherwiseErr(qSupported, "Failed to request supported options");
  conn->parse_supported(qSupported.result.value());

  // IF WE HAVE CFG = NON STOP, REQUEST TO SET IT
  if (conn->settings().is_non_stop) {
    SocketCommand set_non_stop{"QNonStop:1"};
    OkOtherwiseErr(set_non_stop, "Failed to set non-stop mode");
  }

  // READ ALL THREADS THAT REMOTE IS ATTACHED TO
  gdb::qXferCommand read_threads{"qXfer:threads:read:", 0x8000};
  if (!conn->execute_command(read_threads, 0, 1000)) {
    return ConnInitError{.msg = "Failed to determine what processes we are attached to"};
  }

  // DETERMINE WHAT PROCESS SPACES WE ARE ATTACHED TO
  const auto threads = parse_threads(read_threads.response_buffer);

  std::vector<ProcessInfo> pinfo{};

  for (auto &&[pid, tid, name] : threads) {
    auto it = std::ranges::find_if(pinfo, [&](const auto &p) { return p.pid == pid; });
    if (it != std::end(pinfo)) {
      it->threads.push_back({tid, std::move(name)});
    } else {
      char buf[10]{0};
      auto ptr = gdb::format_value(buf, pid);
      gdb::qXferCommand execfile{"qXfer:exec-file:read:", 0x1000, std::string_view{buf, ptr}};
      if (!conn->execute_command(execfile, 0, 1000)) {
        return ConnInitError{.msg = "Failed to get exec file of process"};
      }

      // Gdb does this before requesting target.xml - maybe this is yet another retarded thing about this *SO
      // CALLED* protocol.
      std::array<char, 32> select_thread{};
      auto cmd = SerializeCommand(select_thread, "Hgp{:x}.{:x}", pid, tid);
      SocketCommand select_thread_cmd{cmd};
      OkOtherwiseErr(select_thread_cmd, "Failed to select thread for operation");

      gdb::qXferCommand request_arch_info{"qXfer:features:read:", 0x1000, "target.xml"};
      if (!conn->execute_command(request_arch_info, 0, 1000)) {
        return ConnInitError{.msg = "Failed to get exec file of process"};
      }

      DBGLOG(core, "Target Architecture Description requested:\n{}", request_arch_info.response_buffer);

      xml::XMLParser parser{request_arch_info.response_buffer};
      auto root_element = parser.parse();

      auto arch = gdb::read_arch_info(root_element);

      // Notice that we do not add the "main thread" to the list of threads. Because meta data for that thread
      // is created when we spawn the TraceeController supervisor struct (it creates a normal thread meta data
      // struct for the process)
      pinfo.push_back(
          {execfile.response_buffer, pid, {}, std::make_shared<gdb::ArchictectureInfo>(std::move(arch))});
    }
  }

  // PROCESS STOP REPLIES - THEY WILL GET SENT TO MAIN EVENT LOOP, ESSENTIALLY "STARTING" the session
  if (!threads.empty()) {
    if (auto err = conn->init_stop_query(); err) {
      return err.value();
    }
  }

  std::vector<RemoteProcess> result{};
  result.reserve(pinfo.size());

  for (auto &&proc : pinfo) {
    result.emplace_back(std::move(proc.threads), std::make_unique<GdbRemoteCommander>(
                                                     conn, proc.pid, std::move(proc.exe), std::move(proc.arch)));
  }

  if (result.empty()) {
    return {};
  }
  conn->initialize_thread();
  return result;
}

} // namespace tc
