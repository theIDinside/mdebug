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
  }(__VA_ARGS__)

template <std::integral Value>
static std::string_view
convert_to_target(std::array<char, 16> &outbuf, Value value) noexcept
{
  constexpr auto TSize = sizeof(Value);
  std::array<u8, TSize> bytes{};
  std::memcpy(bytes.data(), &value, TSize);

  auto ptr = outbuf.data();
  for (const auto byte : bytes) {
    auto res = std::to_chars(ptr, ptr + 2, byte, 16);
    ASSERT(res.ec == std::errc(), "to_chars conversion failed");
    ptr = res.ptr;
  }
  return std::string_view{outbuf.data(), ptr};
}

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
  std::array<char, 64> buf{};
  const auto cmd = SerializeCommand(buf, "m{:x},{}", address.get(), size);

  const auto res = connection->send_command_with_response(cmd, 1000);
  if (res.is_error()) {
    return ReadResult::SystemError(0);
  }

  const auto &msg = res.value();
  std::string_view str{msg};
  str.remove_prefix(1);
  auto ptr = read_buffer;

  while (str.size() > 2) {
    if (str[1] == '*') {
      const char c = str[0];
      char repeat_value[2]{c, c};
      const auto hex_encode_repeat_count = static_cast<u32>(str[2] - char{29});
      const auto binary_repeat_count = (hex_encode_repeat_count + 1) / 2;
      u8 value = 0;
      std::from_chars(repeat_value, repeat_value + 2, value, 16);
      std::fill_n(ptr, binary_repeat_count, value);
      ptr += binary_repeat_count;
      str.remove_prefix(3);
    } else {
      auto res = std::from_chars(str.data(), str.data() + 2, *ptr, 16);
      if (res.ec != std::errc()) {
        PANIC("failed to convert read data from memory from hex digits to binary");
      }
      str.remove_prefix(2);
      ++ptr;
    }
  }
  // NOTA BENE: We actually return the *decoded* size of read bytes, not the actual read bytes from the remote.
  // That shit would make no sense, since this is represented by the TraceeCommand interface
  return ReadResult::Ok(ptr - read_buffer);
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

TaskExecuteResponse
GdbRemoteCommander::resume_task(TaskInfo &t, RunType type) noexcept
{
  set_catch_syscalls(type == RunType::SyscallContinue);

  const auto pid = task_leader();
  std::array<char, 128> buf{};
  std::string_view resume_command;
  switch (type) {
  case RunType::Step: {
    resume_command = SerializeCommand(buf, "vCont;s:p{:x}.{:x}", pid, t.tid);
    break;
  }
  case RunType::Continue:
  case RunType::SyscallContinue:
  case RunType::UNKNOWN: {
    resume_command = SerializeCommand(buf, "vCont;c:p{:x}.{:x}", pid, t.tid);
    break;
  }
  }

  const auto resume_err = connection->send_vcont_command(resume_command, {});
  ASSERT(!resume_err.has_value(), "vCont resume command failed");
  t.set_running(type);

  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
GdbRemoteCommander::resume_target(TraceeController *tc, RunType type) noexcept
{
  set_catch_syscalls(type == RunType::SyscallContinue);

  for (auto &t : tc->threads) {
    if (t.loc_stat) {
      t.step_over_breakpoint(tc, tc::ResumeAction{type, tc::ResumeTarget::AllNonRunningInProcess});
      if (!connection->settings().is_non_stop) {
        return TaskExecuteResponse::Ok();
      }
    }
  }

  const auto pid = task_leader();
  std::array<char, 128> buf{};
  std::string_view resume_command;
  switch (type) {
  case RunType::Step: {
    resume_command = SerializeCommand(buf, "vCont;s:p{:x}.-1", pid);
    break;
  }
  case RunType::Continue:
  case RunType::SyscallContinue:
  case RunType::UNKNOWN: {
    resume_command = SerializeCommand(buf, "vCont;c:p{:x}.-1", pid);
    break;
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
  DBGLOG(remote, "Read register field for {}: {}", t.tid, register_contents);

  std::string_view payload{register_contents};

  ASSERT(payload.front() == '$', "Expected OK response");
  payload.remove_prefix(1);

  switch (arch_info->type) {
  case ArchType::X86_64: {
    t.remote_from_hexdigit_encoding(payload);
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
  std::array<char, 64> thr_set_bytes{};
  std::array<char, 64> set_pc_bytes{};
  std::array<char, 16> register_contents{};
  auto register_value = convert_to_target(register_contents, addr.get());
  auto cmds = std::to_array({SerializeCommand(thr_set_bytes, "Hgp{:x}.{:x}", task_leader(), t.tid),
                             SerializeCommand(set_pc_bytes, "P{:x}={}", arch_info->pc_number, register_value)});
  auto response = connection->send_inorder_command_chain(cmds, 1000);
  if (response.is_error()) {
    DBGLOG(remote, "Failed to set pc");
    return TaskExecuteResponse::Error(0);
  }
  auto responses = response.take_value();
  auto i = 0;
  for (const auto &r : responses) {
    if (r != "$OK") {
      DBGLOG(remote, "Response for {} was not OK: {}", cmds[i], r);
      return TaskExecuteResponse::Error(0);
    }
    ++i;
  }

  t.remote_x86_registers()->set_pc(addr);
  return TaskExecuteResponse::Ok(0);
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
  DBGLOG(core, "Perform shut down for GdbRemote Commander - not sure anything's really needed here?");
  return true;
}

bool
GdbRemoteCommander::initialize() noexcept
{
  // TODO(simon): possibly have args to the attach config, where we do some work here, depending on that arg -
  // however, we can *not* wait until now
  //  to actually initialize the remote connection thread. It has to start before this, because it is required to
  //  determine how many targets we have, object files to parse, etc
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

  SocketCommand enable_thread_events{"QThreadEvents:1"};
  OkOtherwiseErr(enable_thread_events, "Failed to set ThreadEvents to ON");

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
