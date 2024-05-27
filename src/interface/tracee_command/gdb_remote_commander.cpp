#include "gdb_remote_commander.h"
#include "common.h"
#include "fmt/core.h"
#include "interface/remotegdb/connection.h"
#include "interface/remotegdb/shared.h"
#include "interface/remotegdb/target_description.h"
#include "interface/tracee_command/tracee_command_interface.h"
// #include "symbolication/dwarf_binary_reader.h"
#include "task.h"
#include "utils/logger.h"
#include "utils/util.h"
#include "utils/xml.h"
#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <sys/user.h>
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

static std::vector<std::tuple<Pid, Tid, std::string>>
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

static ReadResult
convert_to_read_result(const gdb::SendError &err) noexcept
{
  return std::visit(
      [](auto &err) noexcept -> ReadResult {
        using T = ActualType<decltype(err)>;
        // NAck
        if constexpr (std::is_same_v<T, gdb::SystemError>) {
          return ReadResult::SystemError(err.syserrno);
        } else if constexpr (std::is_same_v<T, gdb::Timeout>) {
          return ReadResult::SystemError(0);
        } else if constexpr (std::is_same_v<T, gdb::NAck>) {
          return ReadResult::SystemError(0);
        } else {
          static_assert(always_false<T>, "unhandled branch");
          return ReadResult::SystemError(0);
        }
      },
      err);
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
    return convert_to_read_result(res.error());
  }

  const auto &msg = res.value();
  std::string_view str{msg};
  str.remove_prefix(1);
  auto ptr = read_buffer;
  char dec_buffer[size * 2];
  const auto len = gdb::decode_rle(str, dec_buffer, size * 2);
  std::string_view decoded{dec_buffer, len};
  ASSERT((decoded.size() & 0b1) == 0, "Expected buffer to be divisible by 2");
  while (!decoded.empty()) {
    *ptr = utils::fromhex(decoded[0]) * 16 + utils::fromhex(decoded[1]);
    ++ptr;
    decoded.remove_prefix(2);
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
  if (remote_settings().is_non_stop) {
    std::array<char, 64> bytes{};
    const auto pid = task_leader();
    auto cmd = SerializeCommand(bytes, "vCont;t:p{}.{}", pid, t.tid);
    auto response = connection->send_command_with_response(cmd, 1000);
    if (!(response.is_expected() && response.take_value() == "$OK")) {
      PANIC("Failed to unset breakpoint");
    }
    return TaskExecuteResponse::Ok();
  } else {
    // std::array<char, 64> bytes{};
    // auto cmd = SerializeCommand(bytes, "vCtrlC");
    // auto response = connection->send_command_with_response(cmd, 1000);
    // if (!(response.is_expected() && response.take_value() == "$OK")) {
    //   PANIC("Failed to unset breakpoint");
    // }
    connection->send_interrupt_byte();
    return TaskExecuteResponse::Ok();
  }
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

std::string_view
GdbRemoteCommander::get_thread_name(Tid tid) noexcept
{
  // TODO(Implement name change)
  if (auto opt = utils::find_if(thread_names, [tid](auto &kvp) { return kvp.first == tid; }); opt) {
    return (*opt)->second;
  }
  // READ ALL THREADS THAT REMOTE IS ATTACHED TO

  gdb::qXferCommand read_threads{"qXfer:threads:read:", 0x8000};
  const auto ok = connection->send_qXfer_command_with_response(read_threads, 1000);
  if (!ok) {
    return "";
  }

  // DETERMINE WHAT PROCESS SPACES WE ARE ATTACHED TO
  const auto threads = parse_threads(read_threads.response_buffer);
  for (auto &&[pid, tid, name] : threads) {
    thread_names.emplace(tid, std::move(name));
  }
  return thread_names[tid];
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
GdbRemoteCommander::post_exec() noexcept
{
  Tracer::Instance->load_and_process_objfile(task_leader(), *exec_file);
  if (auto auxv = read_auxv(); auxv.is_expected()) {
    supervisor()->read_auxv_info(std::move(auxv.take_value()));
    tracee_r_debug = supervisor()->install_loader_breakpoints();
  }

  return true;
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
      return {};
    } else {
      exec_file = execfile.response_buffer;
    }
  }
  return exec_file;
}

Tid
GdbRemoteCommander::task_leader() const noexcept
{
  return process_id;
}

std::optional<std::vector<ObjectFileDescriptor>>
GdbRemoteCommander::read_libraries() noexcept
{
  // tracee_r_debug: TPtr<r_debug> points to tracee memory where r_debug lives
  auto rdebug_ext_res = read_type(tracee_r_debug);
  if (rdebug_ext_res.is_error()) {
    DBGLOG(core, "Could not read rdebug_extended");
    return {};
  }
  r_debug_extended rdebug_ext = rdebug_ext_res.take_value();
  std::vector<ObjectFileDescriptor> obj_files{};
  // TODO(simon): Make this asynchronous; so that instead of creating a symbol file inside the loop
  //  instead make a function that returns a promise of a symbol file. That promise gets added to a std::vector on
  //  each loop and then when the while loop has finished, we wait on all promises, collecting them.
  while (true) {
    // means we've hit some "entry" point in the linker-debugger interface; we need to wait for RT_CONSISTENT to
    // safely read "link map" containing the shared objects
    if (rdebug_ext.base.r_state != rdebug_ext.base.RT_CONSISTENT) {
      if (obj_files.empty()) {
        DBGLOG(core, "Debug state not consistent: no information about obj files read");
        return {};
      } else {
        return obj_files;
      }
    }
    auto linkmap = TPtr<link_map>{rdebug_ext.base.r_map};
    while (linkmap != nullptr) {
      auto map_res = read_type(linkmap);
      if (!map_res.is_expected()) {
        DBGLOG(core, "Failed to read linkmap");
        return {};
      }
      auto map = map_res.take_value();
      auto name_ptr = TPtr<char>{map.l_name};
      const auto path = read_nullterminated_string(name_ptr);
      if (!path) {
        DBGLOG(core, "Failed to read null-terminated string from tracee at {}", name_ptr);
      } else {
        obj_files.emplace_back(path.value(), map.l_addr);
      }
      linkmap = TPtr<link_map>{map.l_next};
    }
    const auto next = TPtr<r_debug_extended>{rdebug_ext.r_next};
    if (next != nullptr) {
      const auto next_rdebug = read_type(next);
      if (next_rdebug.is_error()) {
        break;
      } else {
        rdebug_ext = next_rdebug.value();
      }
    } else {
      break;
    }
  }

  return obj_files;
}

std::shared_ptr<gdb::RemoteConnection>
GdbRemoteCommander::remote_connection() noexcept
{
  return connection;
}

utils::Expected<Auxv, Error>
GdbRemoteCommander::read_auxv() noexcept
{
  static constexpr auto BufSize = PAGE_SIZE;
  if (!auxv_data.vector.empty()) {
    return auxv_data;
  } else {
    std::array<char, 64> bytes{};
    auto cmd = SerializeCommand(bytes, "Hgp{:x}.{:x}", task_leader(), task_leader());
    auto set_thread = connection->send_command_with_response(cmd, 1000);

    gdb::qXferCommand read_auxv{"qXfer:auxv:read:", 0x1000};
    const auto result = connection->send_qXfer_command_with_response(read_auxv, 1000);
    if (!result) {
      return Error{.sys_errno = {}, .err_msg = "qXfer command failed"};
    }
    auto buf = std::make_unique<char[]>(BufSize);
    auto d = gdb::decode_rle_to_str(read_auxv.response_buffer, buf.get(), BufSize);
    tc::Auxv aux;
    while (d.size() >= 16) {
      u64 k{0};
      std::memcpy(&k, d.data(), 8);
      d.remove_prefix(8);
      u64 v{0};
      std::memcpy(&v, d.data(), 8);
      aux.vector.push_back({k, v});
      d.remove_prefix(8);
    }
    auxv_data = aux;
    return aux;
  }
}

gdb::RemoteSettings &
GdbRemoteCommander::remote_settings() noexcept
{
  return connection->settings();
}

RemoteSessionConfigurator::RemoteSessionConfigurator(gdb::RemoteConnection::ShrPtr remote) noexcept
    : conn(std::move(remote))
{
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
    return result;
  }
  conn->initialize_thread();
  return result;
}

} // namespace tc
