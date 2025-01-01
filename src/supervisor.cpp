#include "supervisor.h"
#include "bp.h"
#include "common.h"
#include "fmt/core.h"
#include "interface/dap/dap_defs.h"
#include "interface/dap/events.h"
#include "interface/dap/interface.h"
#include "interface/dap/types.h"
#include "interface/tracee_command/gdb_remote_commander.h"
#include "interface/tracee_command/ptrace_commander.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "ptrace.h"
#include "ptracestop_handlers.h"
#include "so_loading.h"
#include "symbolication/block.h"
#include "symbolication/callstack.h"
#include "symbolication/dwarf/lnp.h"
#include "symbolication/dwarf/name_index.h"
#include "symbolication/dwarf_binary_reader.h"
#include "symbolication/dwarf_expressions.h"
#include "symbolication/dwarf_frameunwinder.h"
#include "symbolication/elf.h"
#include "symbolication/elf_symbols.h"
#include "symbolication/objfile.h"
#include "task.h"
#include "tasks/dwarf_unit_data.h"
#include "tasks/index_die_names.h"
#include "tracer.h"
#include "utils/byte_buffer.h"
#include "utils/enumerator.h"
#include "utils/expected.h"
#include "utils/immutable.h"
#include "utils/logger.h"
#include "utils/macros.h"
#include <algorithm>
#include <elf.h>
#include <fcntl.h>
#include <filesystem>
#include <iterator>
#include <link.h>
#include <optional>
#include <ranges>
#include <set>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <utility>

using sym::dw::SourceCodeFile;

// FORK constructor
TraceeController::TraceeController(TraceeController &parent, tc::Interface &&interface) noexcept
    : mTaskLeader{interface->TaskLeaderTid()}, mSymbolFiles(parent.mSymbolFiles),
      mMainExecutable{parent.mMainExecutable}, mThreads{}, mThreadInfos{}, mUserBreakpoints{*this},
      mSharedObjects{parent.mSharedObjects.clone()}, mStopAllTasksRequested{false},
      mInterfaceType{parent.mInterfaceType}, mInterpreterBase{parent.mInterpreterBase}, mEntry{parent.mEntry},
      mSessionKind{parent.mSessionKind}, mStopHandler{new ptracestop::StopHandler{*this}},
      mNullUnwinder{parent.mNullUnwinder}, mTraceeInterface{std::move(interface)}
{
  // Must be set first.
  mTraceeInterface->SetTarget(this);
  mThreads.reserve(64);
  mThreads.push_back(TaskInfo::CreateTask(*mTraceeInterface, mTraceeInterface->TaskLeaderTid(), true));

  mNewObjectFilePublisher.subscribe(SubscriberIdentity::Of(this), [this](const SymbolFile *sf) {
    mDebugAdapterClient->post_event(new ui::dap::ModuleEvent{"new", *sf});
    return true;
  });
}

TraceeController::TraceeController(TargetSession targetSession, tc::Interface &&interface,
                                   InterfaceType type) noexcept
    : mTaskLeader{interface != nullptr ? interface->TaskLeaderTid() : 0}, mMainExecutable{nullptr}, mThreads{},
      mThreadInfos{}, mUserBreakpoints{*this}, mSharedObjects{}, mStopAllTasksRequested{false},
      mInterfaceType(type), mInterpreterBase{}, mEntry{}, mSessionKind{targetSession},
      mStopHandler{new ptracestop::StopHandler{*this}}, mNullUnwinder{new sym::Unwinder{nullptr}},
      mTraceeInterface(std::move(interface))
{
  // Must be set first.
  mTraceeInterface->SetTarget(this);
  mThreads.reserve(64);
  mThreads.push_back(TaskInfo::CreateTask(*mTraceeInterface, mTraceeInterface->TaskLeaderTid(), true));

  mNewObjectFilePublisher.subscribe(SubscriberIdentity::Of(this), [this](const SymbolFile *sf) {
    mDebugAdapterClient->post_event(new ui::dap::ModuleEvent{"new", *sf});
    return true;
  });
}

/*static*/
std::unique_ptr<TraceeController>
TraceeController::create(TargetSession session, tc::Interface &&interface, InterfaceType type)
{
  return std::unique_ptr<TraceeController>(new TraceeController{session, std::move(interface), type});
}

void
TraceeController::TearDown(bool killProcess) noexcept
{
  DBGLOG(core, "Tear down traced process space {} - unclear if this method is needed. Kill={}", mTaskLeader,
         killProcess);
  mIsExited = true;
}

bool TraceeController::IsExited() const noexcept {
  return mIsExited;
}

void
TraceeController::ConfigureDapClient(ui::dap::DebugAdapterClient *client) noexcept
{
  mDebugAdapterClient = client;
}

std::unique_ptr<TraceeController>
TraceeController::Fork(tc::Interface &&interface) noexcept
{
  auto child = std::unique_ptr<TraceeController>(new TraceeController{*this, std::move(interface)});
  return child;
}

TraceeController::~TraceeController() noexcept
{
  /// TODO(simon): Introduce arena allocator per supervisor - this way, when a supervisor dies, it blinks out all
  /// the memory it's consuming without running MANY destructors. We won't be able to just use canonical std::pmr,
  /// we will need to write our own stuff on top of it, for instance
  // some data is shared between supervisors (if their symbolfiles are the same, for instance). But, I'm thinking
  // this won't be that difficult just add some form of reference counting to the actual `SupervisorAllocator`
  // (e.g.) and when it goes to 0 => blink the memory.
  DBGLOG(core, "Destroying supervisor state for {}", mTaskLeader);
}

AddrPtr
TraceeController::EntryAddress() const noexcept
{
  return mEntry.value_or(nullptr);
}

std::shared_ptr<SymbolFile>
TraceeController::LookupSymbolFile(const Path &path) noexcept
{
  for (const auto &s : mSymbolFiles) {
    if (s->GetObjectFile()->IsFile(path)) {
      return s;
    }
  }
  return nullptr;
}

std::vector<ProbeInfo>
parse_stapsdt_note(const Elf *elf, const ElfSection *section) noexcept
{
  std::vector<ProbeInfo> probes;
  DwarfBinaryReader reader{elf, section->mSectionData};
  std::set<std::string_view> required_probes{{"map_complete", "reloc_complete", "unmap_complete"}};
  // stapsdt, location 8 bytes, base 8 bytes, semaphore 8 bytes, desc=string of N bytes, then more bytes we don't
  // care for

  while (reader.has_more() && required_probes.size() > 0) {
    reader.read_value<u32>();
    reader.read_value<u32>();
    reader.read_value<u32>();
    // const auto stapsdt = reader.read_string();
    // ASSERT(stapsdt == "stapsdt", "Failed to see 'stapsdt' deliminator; saw {}", stapsdt);
    // instead just skip:
    reader.skip_string();

    const auto ptr = reader.read_value<u64>();
    // base =
    reader.skip_value<u64>();
    // semaphore =
    reader.skip_value<u64>();

    // same here
    // const auto provider = reader.read_string();
    // ASSERT(provider == "rtld", "Supported provider is rtld, got {}", provider);
    reader.skip_string();
    const auto probe_name = reader.read_string();
    reader.skip_string();
    if (reader.bytes_read() % 4 != 0) {
      reader.skip(4 - reader.bytes_read() % 4);
    }
    if (required_probes.contains(probe_name)) {
      probes.push_back(ProbeInfo{.address = ptr, .name = std::string{probe_name}});
      required_probes.erase(required_probes.find(probe_name));
    }
  }
  return probes;
}

auto
createSymbolFile(auto &tc, auto path, AddrPtr addr) noexcept -> std::shared_ptr<SymbolFile>
{
  auto existing_obj = Tracer::Instance->LookupSymbolfile(path);
  if (existing_obj) {
    // if baseAddr == addr; unique = false, return null, because we've already registered it
    return existing_obj->mBaseAddress != addr ? existing_obj->Copy(tc, addr) : nullptr;
  } else {
    auto obj = ObjectFile::CreateObjectFile(&tc, path);
    if (obj != nullptr) {
      return SymbolFile::Create(&tc, std::move(obj), addr);
    }
  }
  return nullptr;
}

static TPtr<r_debug_extended>
get_rdebug_state(ObjectFile *obj_file)
{
  const auto rdebug_state = obj_file->FindMinimalObjectSymbol(LOADER_STATE);
  ASSERT(rdebug_state.has_value(), "Could not find _r_debug!");
  return rdebug_state->address.as<r_debug_extended>();
}

TPtr<r_debug_extended>
TraceeController::InstallDynamicLoaderBreakpoints() noexcept
{
  ASSERT(mMainExecutable != nullptr, "No main executable for this target");
  const auto mainExecutableElf = mMainExecutable->GetObjectFile()->GetElf();
  auto int_path = interpreter_path(mainExecutableElf, mainExecutableElf->GetSection(".interp"));
  auto tmp_objfile = ObjectFile::CreateObjectFile(this, int_path);
  ASSERT(tmp_objfile != nullptr, "Failed to mmap the loader binary");
  const auto system_tap_sec = tmp_objfile->GetElf()->GetSection(".note.stapsdt");
  const auto probes = parse_stapsdt_note(tmp_objfile->GetElf(), system_tap_sec);

  mTraceeInterface->tracee_r_debug = *mInterpreterBase + get_rdebug_state(tmp_objfile.get());
  DBGLOG(core, "_r_debug found at {}", mTraceeInterface->tracee_r_debug);
  for (const auto symbol_name : LOADER_SYMBOL_NAMES) {
    if (auto symbol = tmp_objfile->FindMinimalFunctionSymbol(symbol_name); symbol) {
      const auto addr = *mInterpreterBase + symbol->address;
      DBGLOG(core, "Setting ld breakpoint at 0x{:x}", addr);
      mUserBreakpoints.create_loc_user<SOLoadingBreakpoint>(*this, GetOrCreateBreakpointLocation(addr),
                                                            mTaskLeader);
    }
  }

  return mTraceeInterface->tracee_r_debug;
}

void
TraceeController::OnSharedObjectEvent() noexcept
{
  DBGLOG(core, "so event triggered");
  if (const auto libs_result = mTraceeInterface->ReadLibraries(); libs_result) {
    std::vector<std::shared_ptr<SymbolFile>> obj_files{};
    const auto &libs = libs_result.value();
    DBGLOG(core, "Object File Descriptors read: {}", libs.size());
    for (const auto &[path, l_addr] : libs) {
      auto symbolFile = createSymbolFile(*this, path, l_addr);
      if (symbolFile) {
        obj_files.push_back(symbolFile);
        RegisterSymbolFile(symbolFile, false);
      }
    }
    DoBreakpointsUpdate(std::move(obj_files));
  } else {
    DBGLOG(core, "No library info was returned");
  }
}

bool
TraceeController::IsNullUnwinder(sym::Unwinder *unwinder) const noexcept
{
  return unwinder == mNullUnwinder;
}

bool
TraceeController::IsIndividualTaskControlConfigured() noexcept
{
  return false;
}

void
TraceeController::AddTask(std::shared_ptr<TaskInfo> &&task) noexcept
{
  mThreads.push_back(std::move(task));
}

u32
TraceeController::RemoveTaskIf(std::function<bool(const std::shared_ptr<TaskInfo> &)> &&predicate)
{
  auto count = mThreads.size();
  auto removeIterator = std::remove_if(mThreads.begin(), mThreads.end(), predicate);
  mThreads.erase(removeIterator, mThreads.end());
  return count - mThreads.size();
}

std::span<std::shared_ptr<TaskInfo>>
TraceeController::GetThreads() noexcept
{
  return mThreads;
}

Tid
TraceeController::TaskLeaderTid() const noexcept
{
  return mTaskLeader;
}

TaskInfo *
TraceeController::GetTaskByTid(pid_t tid) noexcept
{
  for (auto &t : mThreads) {
    if (t->tid == tid) {
      return t.get();
    }
  }
  return nullptr;
}

UserBreakpoints &
TraceeController::GetUserBreakpoints() noexcept
{
  return mUserBreakpoints;
}

void
TraceeController::CreateNewTask(Tid tid, bool running) noexcept
{
  ASSERT(tid != 0 && !HasTask(tid), "Task {} has already been created!", tid);
  mThreads.push_back(TaskInfo::CreateTask(*mTraceeInterface, tid, running));
}

bool
TraceeController::HasTask(Tid tid) noexcept
{
  for (const auto &task : mThreads) {
    if (task->tid == tid) {
      return true;
    }
  }
  return false;
}

void
TraceeController::ResumeTask(tc::RunType type) noexcept
{
  DBGLOG(core, "[supervisor]: resume tracee {}", to_str(type));
  mStopAllTasksRequested = false;
  mTraceeInterface->ResumeTarget(this, type);
}

void
TraceeController::ResumeTask(TaskInfo &task, tc::ResumeAction type) noexcept
{
  mStopAllTasksRequested = false;
  bool resume_task = !(task.loc_stat);
  // The breakpoint location which loc_stat refers to, may have been deleted; as such we don't need to step over
  // that breakpoint any more but we will need to remove the loc stat on this task.
  if (task.loc_stat) {
    auto location = mUserBreakpoints.location_at(task.loc_stat->loc);
    if (location) {
      task.step_over_breakpoint(this, type);
    } else {
      task.clear_bpstat();
      resume_task = true;
    }
  }

  // we do it like this, to not have to say tc->resume_task(...) in multiple places.
  if (resume_task) {
    const auto res = mTraceeInterface->ResumeTask(task, type.type);
    CDLOG(!res.is_ok(), core, "Unable to resume task {}: {}", task.tid, strerror(res.sys_errno));
  }
  task.wait_status = WaitStatus{WaitStatusKind::NotKnown, {}};
  task.clear_stop_state();
}

void
TraceeController::StopAllTasks(TaskInfo *requestingTask) noexcept
{
  DBGLOG(core, "Stopping all threads")
  mStopAllTasksRequested = true;
  for (auto &task : mThreads) {
    auto &t = *task;
    if (!t.user_stopped && !t.tracer_stopped) {
      DBGLOG(core, "Stopping {}", t.tid);
      const auto response = mTraceeInterface->StopTask(t);
      ASSERT(response.is_ok(), "Failed to stop {}: {}", t.tid, strerror(response.sys_errno));
      t.set_stop();
    } else if (t.tracer_stopped) {
      // we're in a tracer-stop, not in a user-stop, so we need no stopping, we only need to inform ourselves that
      // we upgraded our tracer-stop to a user-stop
      t.set_stop();
    }
    // if the stop is requested by `requesting_task` we don't want
    // to remove it's ptrace action as it might be the one requesting the stop
    if (&t != requestingTask) {
      auto action = mStopHandler->get_proceed_action(t);
      if (action) {
        action->cancel();
        mStopHandler->remove_action(t);
      }
    }
  }
}

TaskInfo *
TraceeController::RegisterTaskWaited(TaskWaitResult wait) noexcept
{
  ASSERT(HasTask(wait.tid), "Target did not contain task {}", wait.tid);
  auto task = GetTaskByTid(wait.tid);
  task->set_taskwait(wait);
  task->tracer_stopped = true;
  return task;
}

AddrPtr
TraceeController::CacheAndGetPcFor(TaskInfo &t) noexcept
{
  if (t.rip_dirty) {
    CacheRegistersFor(t);
  }
  return t.regs.GetPc();
}

void
TraceeController::SetProgramCounterFor(TaskInfo &task, AddrPtr addr) noexcept
{
  auto res = mTraceeInterface->SetProgramCounter(task, addr);
  ASSERT(res.is_ok(), "Failed to set PC for {}; {}", task.tid, strerror(res.sys_errno));
  task.rip_dirty = false;
}

void
TraceeController::SetTaskVmInfo(Tid tid, TaskVMInfo vmInfo) noexcept
{
  ASSERT(HasTask(tid), "Unknown task {}", tid);
  mThreadInfos[tid] = vmInfo;
}

void
TraceeController::SetIsOnEntry(bool setting) noexcept
{
  mOnEntry = setting;
}

bool
TraceeController::IsOnEntry() const noexcept
{
  return mOnEntry;
}

void
TraceeController::EmitStoppedAtBreakpoints(LWP lwp, u32 bp_id, bool allStopped) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  DBGLOG(core, "[dap event]: stopped at breakpoint {} emitted", bp_id);
  auto evt =
    new ui::dap::StoppedEvent{ui::dap::StoppedReason::Breakpoint, "Breakpoint Hit", lwp.tid, {}, "", allStopped};
  evt->bp_ids.push_back(bp_id);
  mDebugAdapterClient->post_event(evt);
}

void
TraceeController::EmitSteppedStop(LWP lwp) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  EmitSteppedStop(lwp, "Stepping finished", false);
}

void
TraceeController::EmitSteppedStop(LWP lwp, std::string_view message, bool allStopped) noexcept
{
  mDebugAdapterClient->post_event(
    new ui::dap::StoppedEvent{ui::dap::StoppedReason::Step, message, lwp.tid, {}, "", allStopped});
}

void
TraceeController::EmitSignalEvent(LWP lwp, int signal) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  mDebugAdapterClient->post_event(new ui::dap::StoppedEvent{
    ui::dap::StoppedReason::Exception, fmt::format("Signalled {}", signal), lwp.tid, {}, "", true});
}

void
TraceeController::EmitStopped(Tid tid, ui::dap::StoppedReason reason, std::string_view message, bool allStopped,
                              std::vector<int> bps_hit) noexcept
{
  mDebugAdapterClient->post_event(
    new ui::dap::StoppedEvent{reason, message, tid, std::move(bps_hit), message, allStopped});
}

void
TraceeController::EmitBreakpointEvent(std::string_view reason, const UserBreakpoint &bp,
                                      std::optional<std::string> message) noexcept
{
  mDebugAdapterClient->post_event(new ui::dap::BreakpointEvent{reason, std::move(message), &bp});
}

tc::ProcessedStopEvent
TraceeController::ProcessDeferredStopEvent(TaskInfo &, DeferToSupervisor &) noexcept
{
  TODO("implement TraceeController::process_deferred_stopevent(TaskInfo &t, DeferToSupervisor &evt) noexcept");
}

utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr>
TraceeController::GetOrCreateBreakpointLocation(AddrPtr addr) noexcept
{
  if (auto loc = mUserBreakpoints.location_at(addr); loc) {
    return loc;
  }

  auto res = InstallSoftwareBreakpointLocation(addr);
  if (!res.is_expected()) {
    return utils::unexpected(res.take_error());
  }
  const auto original_byte = res.take_value();
  return BreakpointLocation::CreateLocation(addr, original_byte);
}

utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr>
TraceeController::GetOrCreateBreakpointLocation(AddrPtr addr, sym::dw::SourceCodeFile &sourceFile,
                                                const sym::dw::LineTableEntry &lte) noexcept
{
  auto loc = mUserBreakpoints.location_at(addr);
  if (loc) {
    return loc;
  }

  auto res = InstallSoftwareBreakpointLocation(addr);
  if (!res.is_expected()) {
    return res.take_error();
  }
  auto original_byte = res.take_value();
  return BreakpointLocation::CreateLocationWithSource(
    addr, original_byte,
    std::make_unique<LocationSourceInfo>(sourceFile.full_path->string(), lte.line, u32{lte.column}));
}

utils::Expected<std::shared_ptr<BreakpointLocation>, BpErr>
TraceeController::GetOrCreateBreakpointLocationWithSourceLoc(
  AddrPtr addr, std::optional<LocationSourceInfo> &&sourceLocInfo) noexcept
{
  if (auto loc = mUserBreakpoints.location_at(addr); loc) {
    return loc;
  }

  auto res = InstallSoftwareBreakpointLocation(addr);
  if (!res.is_expected()) {
    return res.take_error();
  }
  auto original_byte = res.take_value();
  if (sourceLocInfo) {
    return BreakpointLocation::CreateLocationWithSource(
      addr, original_byte, std::make_unique<LocationSourceInfo>(std::move(sourceLocInfo.value())));
  } else {
    return BreakpointLocation::CreateLocation(addr, original_byte);
  }
}

bool
TraceeController::CheckBreakpointLocationsForSymbolFile(
  SymbolFile &symbolFile, UserBreakpoint &user, std::vector<std::shared_ptr<BreakpointLocation>> &locs) noexcept
{
  const auto sz = locs.size();
  if (auto specPtr = user.user_spec(); specPtr != nullptr) {
    auto objfile = symbolFile.GetObjectFile();
    switch (specPtr->index()) {
    case UserBreakpoint::SOURCE_BREAKPOINT: {
      const auto &spec = std::get<std::pair<std::string, SourceBreakpointSpec>>(*specPtr);
      const auto predicate = [&srcSpec = spec.second](const sym::dw::LineTableEntry &entry) {
        return srcSpec.line == entry.line && srcSpec.column.value_or(entry.column) == entry.column &&
               !entry.IsEndOfSequence;
      };
      for (auto &sourceCodeFile : objfile->GetSourceCodeFiles(spec.first)) {
        std::vector<sym::dw::LineTableEntry> entries;
        sourceCodeFile->ReadInSourceCodeLineTable(entries);

        for (const auto &lte : entries | std::views::filter(predicate)) {
          const auto pc = lte.pc + symbolFile.mBaseAddress;
          if (auto res = GetOrCreateBreakpointLocation(pc, *sourceCodeFile, lte); res.is_expected()) {
            locs.push_back(res.take_value());
            if (!spec.second.column.has_value()) {
              break;
            }
          }
        }
      }
    } break;
    case UserBreakpoint::FUNCTION_BREAKPOINT: {
      const auto &spec = std::get<FunctionBreakpointSpec>(*specPtr);
      auto result = symbolFile.LookupBreakpointBySpec(spec);

      if (auto it =
            std::find_if(result.begin(), result.end(), [](const auto &it) { return it.loc_src_info.has_value(); });
          it != end(result)) {
        if (auto res =
              GetOrCreateBreakpointLocationWithSourceLoc(it->address, std::move(it->loc_src_info.value()));
            res.is_expected()) {
          locs.push_back(res.take_value());
        }
      } else {
        for (auto &&lookup : result) {
          if (auto res = GetOrCreateBreakpointLocation(lookup.address); res.is_expected()) {
            locs.push_back(res.take_value());
          }
        }
      }
    } break;
    case UserBreakpoint::INSTRUCTION_BREAKPOINT:
      const auto &spec = std::get<InstructionBreakpointSpec>(*specPtr);
      auto addr_opt = to_addr(spec.instructionReference);
      ASSERT(addr_opt.has_value(), "Failed to convert instructionReference to valid address");
      const auto addr = addr_opt.value();
      if (symbolFile.ContainsProgramCounter(addr)) {
        if (auto res = GetOrCreateBreakpointLocation(addr); res.is_expected()) {
          locs.push_back(res.take_value());
        }
      }
      break;
    }
  }

  // No new breakpoint location could be found in symbol file.
  return locs.size() != sz;
}

void
TraceeController::DoBreakpointsUpdate(std::vector<std::shared_ptr<SymbolFile>> &&newSymbolFiles) noexcept
{
  DBGLOG(core, "[breakpoints]: Updating breakpoints due to new symbol files");

  // Check all existing breakpoints and those who are verified = false, check if they can be verified against the
  // new object files (and thus actually be set)
  auto non_verified = mUserBreakpoints.non_verified();
  for (auto &user : non_verified) {
    for (auto &symbol_file : newSymbolFiles) {
      // this user breakpoint was verified on previous iteration (i.e in another symbol file)
      if (user->verified()) {
        break;
      }
      std::vector<std::shared_ptr<BreakpointLocation>> newLocations;
      if (CheckBreakpointLocationsForSymbolFile(*symbol_file, *user, newLocations)) {
        newLocations.back()->add_user(GetInterface(), *user);
        user->update_location(std::move(newLocations.back()));
        mUserBreakpoints.add_bp_location(*user);
        mDebugAdapterClient->post_event(new ui::dap::BreakpointEvent{"changed", {}, user.get()});
        newLocations.pop_back();

        for (auto &&loc : newLocations) {
          auto newUser = user->CloneBreakpoint(mUserBreakpoints, *this, loc);
          mDebugAdapterClient->post_event(new ui::dap::BreakpointEvent{"new", {}, newUser.get()});
          ASSERT(!loc->loc_users().empty(), "location has no user!");
        }
        newLocations.clear();
      }
    }
  }

  // Create new breakpoints, based on source specification or fn name spec, if they exist in new object files
  using Entry = sym::dw::LineTableEntry;

  // Do update for "source breakpoints", breakpoints set via a source spec
  for (auto &&sym : newSymbolFiles) {
    auto obj = sym->GetObjectFile();
    for (const auto &source_file : mUserBreakpoints.sources_with_bpspecs()) {
      auto &file_bp_map = mUserBreakpoints.bps_for_source(source_file);
      for (auto &sourceCodeFile : obj->GetSourceCodeFiles(source_file)) {
        std::vector<Entry> entries;
        for (auto &[desc, user_ids] : file_bp_map) {
          entries.clear();
          const auto predicate = [&desc](const Entry &lte) {
            return lte.line == desc.line && desc.column.value_or(lte.column) == lte.column && !lte.IsEndOfSequence;
          };
          sourceCodeFile->ReadInSourceCodeLineTable(entries);
          for (const auto &e : entries | std::views::filter(predicate)) {
            const auto pc = AddrPtr{e.pc + sym->mBaseAddress};
            bool same_src_loc_different_pc = false;
            for (const auto id : user_ids) {
              auto user = mUserBreakpoints.get_user(id);
              if (user->address() != pc) {
                same_src_loc_different_pc = true;
              }
            }
            if (same_src_loc_different_pc) {
              std::unique_ptr<UserBpSpec> spec =
                std::make_unique<UserBpSpec>(std::make_pair(std::string{source_file}, desc));
              auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
                *this, GetOrCreateBreakpointLocation(pc, *sourceCodeFile, e), mTaskLeader,
                LocationUserKind::Source, std::nullopt, std::nullopt, !IsIndividualTaskControlConfigured(),
                std::move(spec));
              mDebugAdapterClient->post_event(new ui::dap::BreakpointEvent{"new", {}, user.get()});
              user_ids.push_back(user->id);
              DBGLOG(core, "[bkpt:source]: added bkpt at 0x{}", pc);
            }
          }
        }
      }
    }

    // Do update for "function breakpoints", set via a name or regex of a function name spec.
    for (auto &[fn, ids] : mUserBreakpoints.fn_breakpoints) {
      auto result = sym->LookupBreakpointBySpec(fn);
      for (auto &&lookup : result) {
        auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
          *this, GetOrCreateBreakpointLocationWithSourceLoc(lookup.address, std::move(lookup.loc_src_info)),
          mTaskLeader, LocationUserKind::Function, std::nullopt, std::nullopt,
          !IsIndividualTaskControlConfigured(), std::make_unique<UserBpSpec>(fn));
        mDebugAdapterClient->post_event(new ui::dap::BreakpointEvent{"new", {}, user.get()});
        ids.push_back(user->id);
      }
    }
  }
}

void
TraceeController::UpdateSourceBreakpoints(const std::filesystem::path &sourceFilePath,
                                          std::vector<SourceBreakpointSpec> &&add,
                                          const std::vector<SourceBreakpointSpec> &remove) noexcept
{
  UserBreakpoints::SourceFileBreakpointMap &map = mUserBreakpoints.bps_for_source(sourceFilePath.string());

  Set<SourceBreakpointSpec> not_set{add.begin(), add.end()};

  for (const auto &symbol_file : mSymbolFiles) {
    auto obj = symbol_file->GetObjectFile();
    for (auto &sourceCodeFile : obj->GetSourceCodeFiles(sourceFilePath.c_str())) {
      // TODO(simon): use arena allocator for foundEntries
      std::vector<sym::dw::LineTableEntry> foundEntries;
      for (const auto &sourceSpec : add) {
        foundEntries.clear();
        sourceCodeFile->ReadInSourceCodeLineTable(foundEntries);
        const auto predicate = [&sourceSpec](const sym::dw::LineTableEntry &entry) {
          if (entry.IsEndOfSequence) {
            return false;
          }
          return sourceSpec.line == entry.line && sourceSpec.column.value_or(entry.column) == entry.column;
        };
        for (const auto &e : foundEntries | std::views::filter(predicate)) {
          const auto pc = e.pc + symbol_file->mBaseAddress;
          auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
            *this, GetOrCreateBreakpointLocation(pc, *sourceCodeFile, e), mTaskLeader, LocationUserKind::Source,
            std::nullopt, std::nullopt, !IsIndividualTaskControlConfigured(),
            std::make_unique<UserBpSpec>(std::make_pair(sourceFilePath.string(), sourceSpec)));
          map[sourceSpec].push_back(user->id);
          DBGLOG(core, "[bkpt:source]: added bkpt at 0x{:x}, orig_byte=0x{:x}", pc,
                 user->bp_location() != nullptr ? *user->bp_location()->original_byte : u8{0});
          if (const auto it = not_set.find(sourceSpec); it != std::end(not_set)) {
            not_set.erase(it);
          }
          if (!sourceSpec.column.has_value()) {
            break;
          }
        }
      }
    }
  }

  // set User Breakpoints without breakpoint location; i.e. "pending" breakpoints, in GDB nomenclature
  for (auto &&srcbp : not_set) {
    auto spec = std::make_unique<UserBpSpec>(std::make_pair(sourceFilePath.string(), srcbp));
    auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
      *this, BpErr{ResolveError{.spec = spec.get()}}, mTaskLeader, LocationUserKind::Source, std::nullopt,
      std::nullopt, !IsIndividualTaskControlConfigured(), std::move(spec));
    map[srcbp].push_back(user->id);
  }

  for (const auto &bp : remove) {
    auto iter = map.find(bp);
    for (const auto id : iter->second) {
      mUserBreakpoints.remove_bp(id);
    }
    map.erase(map.find(bp));
  }
}

void
TraceeController::SetSourceBreakpoints(const std::filesystem::path &sourceFilePath,
                                       const Set<SourceBreakpointSpec> &bps) noexcept
{
  const UserBreakpoints::SourceFileBreakpointMap &map = mUserBreakpoints.bps_for_source(sourceFilePath.string());
  std::vector<SourceBreakpointSpec> remove{};
  std::vector<SourceBreakpointSpec> add{};
  for (const auto &[b, id] : map) {
    if (!bps.contains(b)) {
      remove.push_back(b);
    }
  }

  for (const auto &b : bps) {
    if (!map.contains(b)) {
      add.push_back(b);
    }
  }

  UpdateSourceBreakpoints(sourceFilePath, std::move(add), remove);
}

void
TraceeController::SetInstructionBreakpoints(const Set<InstructionBreakpointSpec> &bps) noexcept
{
  std::vector<InstructionBreakpointSpec> add{};
  std::vector<InstructionBreakpointSpec> remove{};

  for (const auto &[bp, id] : mUserBreakpoints.instruction_breakpoints) {
    if (!bps.contains(bp)) {
      remove.push_back(bp);
    }
  }

  for (const auto &bp : bps) {
    if (!mUserBreakpoints.instruction_breakpoints.contains(bp)) {
      add.push_back(bp);
    }
  }

  for (const auto &bp : add) {
    auto addr = to_addr(bp.instructionReference).value();
    bool was_not_set = true;
    if (auto symbolFile = FindObjectByPc(addr); symbolFile) {
      auto cus = symbolFile->GetCompilationUnits(addr);
      for (auto cu : cus) {
        auto [src, lte] = cu->GetLineTableEntry(symbolFile->UnrelocateAddress(addr));
        if (src && lte) {
          const auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
            *this, GetOrCreateBreakpointLocation(addr, *src, *lte), mTaskLeader, LocationUserKind::Address,
            std::nullopt, std::nullopt, !IsIndividualTaskControlConfigured(), std::make_unique<UserBpSpec>(bp));
          mUserBreakpoints.instruction_breakpoints[bp] = user->id;
          was_not_set = false;
          break;
        }
      }
    }
    if (was_not_set) {
      const auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
        *this, GetOrCreateBreakpointLocation(addr), mTaskLeader, LocationUserKind::Address, std::nullopt,
        std::nullopt, !IsIndividualTaskControlConfigured(), std::make_unique<UserBpSpec>(bp));
      mUserBreakpoints.instruction_breakpoints[bp] = user->id;
    }
  }

  for (const auto &bp : remove) {
    auto iter = mUserBreakpoints.instruction_breakpoints.find(bp);
    ASSERT(iter != std::end(mUserBreakpoints.instruction_breakpoints), "Expected to find breakpoint");
    mUserBreakpoints.remove_bp(iter->second);
    mUserBreakpoints.instruction_breakpoints.erase(iter);
  }
}

void
TraceeController::SetFunctionBreakpoints(const Set<FunctionBreakpointSpec> &bps) noexcept
{
  std::vector<FunctionBreakpointSpec> remove{};
  struct SpecWasSet
  {
    FunctionBreakpointSpec mSpec;
    size_t mSpecHash;
    bool mWasSet;
  };

  std::vector<SpecWasSet> specsToAdd;

  for (const auto &[b, id] : mUserBreakpoints.fn_breakpoints) {
    if (!bps.contains(b)) {
      remove.push_back(b);
    }
  }
  std::hash<FunctionBreakpointSpec> specHasher{};
  for (const auto &b : bps) {
    if (!mUserBreakpoints.fn_breakpoints.contains(b)) {
      specsToAdd.push_back({b, specHasher(b), false});
    }
  }

  for (auto &sym : mSymbolFiles) {
    for (auto &fn : specsToAdd) {
      auto result = sym->LookupBreakpointBySpec(fn.mSpec);
      for (auto &&lookup : result) {
        auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
          *this, GetOrCreateBreakpointLocationWithSourceLoc(lookup.address, std::move(lookup.loc_src_info)),
          mTaskLeader, LocationUserKind::Function, std::nullopt, std::nullopt,
          !IsIndividualTaskControlConfigured(), std::make_unique<UserBpSpec>(fn.mSpec));
        mUserBreakpoints.fn_breakpoints[fn.mSpec].push_back(user->id);
        fn.mWasSet = true;
        mDebugAdapterClient->post_event(new ui::dap::BreakpointEvent{"new", "Breakpoint was created", user.get()});
      }
    }
  }

  for (auto &&[spec, specHash, wasSet] : specsToAdd) {
    if (!wasSet) {
      auto spec_ptr = std::make_unique<UserBpSpec>(std::move(spec));
      auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
        *this, BpErr{ResolveError{.spec = spec_ptr.get()}}, mTaskLeader, LocationUserKind::Function, std::nullopt,
        std::nullopt, !IsIndividualTaskControlConfigured(), std::move(spec_ptr));
    }
  }

  for (const auto &to_remove : remove) {
    auto iter = mUserBreakpoints.fn_breakpoints.find(to_remove);
    ASSERT(iter != std::end(mUserBreakpoints.fn_breakpoints), "Expected to find fn breakpoint in map");

    for (auto id : iter->second) {
      mUserBreakpoints.remove_bp(id);
    }
    mUserBreakpoints.fn_breakpoints.erase(iter);
  }
}

void
TraceeController::RemoveBreakpoint(u32 breakpointId) noexcept
{
  mUserBreakpoints.remove_bp(breakpointId);
}

bool
TraceeController::TryTerminateGracefully() noexcept
{
  DBGLOG(core, "[TraceeController]: terminate gracefully");
  if (IsRunning()) {
    StopAllTasks(nullptr);
  }

  return ::kill(mTaskLeader, SIGKILL) == 0;
}

void
TraceeController::SetAndCallRunAction(Tid tid, ptracestop::ThreadProceedAction *action) noexcept
{
  mStopHandler->set_and_run_action(tid, action);
}

void
TraceeController::PostExec(const std::string &exe) noexcept
{
  DBGLOG(core, "Processing EXEC for {}", mTaskLeader);
  if (mMainExecutable) {
    mMainExecutable = nullptr;
  }
  mSymbolFiles.clear();
  mUserBreakpoints.on_exec();

  auto t = GetTaskByTid(TaskLeaderTid());
  CacheRegistersFor(*t);

  if (mTraceeInterface->mType == tc::TraceeInterfaceType::Ptrace) {
    mTraceeInterface->OnExec();
  }

  auto auxv_result = mTraceeInterface->ReadAuxiliaryVector().expected("Failed to read auxv");
  const auto parsedAux = ParsedAuxiliaryVectorData(auxv_result);
  mAuxiliaryVector = std::move(auxv_result);
  mInterpreterBase = parsedAux.mInterpreterBaseAddress;
  mEntry = parsedAux.mEntry;

  std::vector<u8> programHeaderContents{};
  programHeaderContents.resize(parsedAux.mProgramHeaderEntrySize * parsedAux.mProgramHeaderCount, 0);
  const auto readResult = mTraceeInterface->ReadBytes(parsedAux.mProgramHeaderPointer,
                                                      programHeaderContents.size(), programHeaderContents.data());
  ASSERT(readResult.success(), "Failed to read program headers");

  Elf64_Phdr *cast = (Elf64_Phdr *)programHeaderContents.data();
  AddrPtr baseAddress = nullptr;
  for (auto i = 0u; i < parsedAux.mProgramHeaderCount; ++i) {
    if ((cast + i)->p_type == PT_PHDR) {
      baseAddress = parsedAux.mProgramHeaderPointer - (cast + i)->p_offset;
      DBGLOG(core, "Found base address in program header data in loaded binary: {}", baseAddress);
    }
  }

  if (auto symbol_obj = Tracer::Instance->LookupSymbolfile(exe); symbol_obj == nullptr) {
    auto obj = ObjectFile::CreateObjectFile(this, exe);
    if (obj->GetElf()->AddressesNeedsRelocation()) {
      RegisterObjectFile(this, std::move(obj), true, baseAddress);
    } else {
      RegisterObjectFile(this, std::move(obj), true, nullptr);
    }
  } else {
    RegisterSymbolFile(symbol_obj, true);
  }

  mTraceeInterface->tracee_r_debug = InstallDynamicLoaderBreakpoints();
}

bool
TraceeController::ExecutionHasNotEnded() const noexcept
{
  return !mThreads.empty();
}

bool
TraceeController::IsRunning() const noexcept
{
  return std::any_of(mThreads.cbegin(), mThreads.cend(), [](const std::shared_ptr<TaskInfo> &t) {
    DBGLOG(core, "Thread {} stopped={}", t->tid, t->is_stopped());
    return !t->is_stopped();
  });
}

void
TraceeController::RegisterSymbolFile(std::shared_ptr<SymbolFile> symbolFile, bool isMainExecutable) noexcept
{
  const auto it = std::find_if(mSymbolFiles.begin(), mSymbolFiles.end(), [&symbolFile](auto &s) {
    return symbolFile->GetObjectFilePath() == s->GetObjectFilePath();
  });
  if (it != std::end(mSymbolFiles)) {
    const auto same_bounds = symbolFile->mPcBounds == (*it)->mPcBounds;
    DBGLOG(core, "[symbol file]: Already added {} at {} .. {}; new is at {}..{} - Same range?: {}",
           symbolFile->GetObjectFilePath().c_str(), (*it)->LowProgramCounter(), (*it)->HighProgramCounter(),
           symbolFile->LowProgramCounter(), symbolFile->HighProgramCounter(), same_bounds)
    return;
  }
  mSymbolFiles.emplace_back(symbolFile);

  if (isMainExecutable) {
    mMainExecutable = mSymbolFiles.back();
  }

  // todo(simon): optimization possible; insert in a sorted fashion instead.
  std::sort(mSymbolFiles.begin(), mSymbolFiles.end(), [&symbolFile](auto &&a, auto &&b) {
    ASSERT(a->LowProgramCounter() != b->LowProgramCounter(),
           "[{}]: Added object files with identical address ranges. We screwed something up, for sure\na={}\nb={}",
           symbolFile->GetObjectFilePath().c_str(), a->GetObjectFilePath().c_str(),
           b->GetObjectFilePath().c_str());
    return a->LowProgramCounter() < b->LowProgramCounter() && a->HighProgramCounter() < b->HighProgramCounter();
  });
  mNewObjectFilePublisher.emit(symbolFile.get());
}

// Debug Symbols Related Logic
void
TraceeController::RegisterObjectFile(TraceeController *tc, std::shared_ptr<ObjectFile> &&obj,
                                     bool isMainExecutable, AddrPtr relocatedBase) noexcept
{
  ASSERT(obj != nullptr, "Object file is null");
  RegisterSymbolFile(SymbolFile::Create(tc, std::move(obj), relocatedBase), isMainExecutable);
}

struct AuxvPair
{
  u64 key, value;
};

void
TraceeController::ParseAuxiliaryVectorInfo(tc::Auxv &&aux) noexcept
{
  mAuxiliaryVector = std::move(aux);

  for (const auto [id, value] : mAuxiliaryVector.vector) {
    if (id == AT_BASE) {
      DBGLOG(core, "interpreter base found: 0x{:x}", value);
      mInterpreterBase = value;
    }
    if (id == AT_ENTRY) {
      DBGLOG(core, "Entry found: 0x{:x}", value);
      mEntry = value;
    }
  }
}

void
TraceeController::ReadAuxiliaryVector(TaskInfo &task)
{
  ASSERT(task.wait_status.ws == WaitStatusKind::Execed,
         "Reading AUXV using this function does not make sense if's not *right* after an EXEC");
  CacheRegistersFor(task);
  TPtr<i64> stack_ptr = task.regs.registers->rsp;
  i64 argc = ReadType(stack_ptr);

  stack_ptr += argc + 1;
  ASSERT(ReadType(stack_ptr) == 0, "Expected null terminator after argv at {}", stack_ptr);
  stack_ptr++;
  auto envp = stack_ptr.as<const char *>();
  // we're at the envp now, that pointer list is also terminated by a nullptr
  while (ReadType(envp) != nullptr) {
    envp++;
  }
  // We should now be at Auxilliary Vector Table (see `man getauxval` for info, we're interested in the
  // interpreter base address)

  envp++;
  // cast it to our own type
  auto aux_ptr = envp.as<AuxvPair>();
  std::vector<AuxvPair> auxv{};
  for (;;) {
    auto kvp = ReadType(aux_ptr);
    auxv.push_back(kvp);
    // terminated by a "null entry"
    if (kvp.key == 0) {
      break;
    }
    aux_ptr++;
  }

  for (const auto &kvp : auxv) {
    if (kvp.key == AT_BASE) {
      mInterpreterBase = kvp.value;
    }
    if (kvp.key == AT_ENTRY) {
      mEntry = kvp.value;
    }
  }

  ASSERT(mEntry.has_value() && mInterpreterBase.has_value(), "Expected ENTRY and INTERPRETER_BASE to be found");
}

TargetSession
TraceeController::GetSessionType() const noexcept
{
  return mSessionKind;
}

utils::Expected<std::unique_ptr<utils::ByteBuffer>, NonFullRead>
TraceeController::SafeRead(AddrPtr addr, u64 bytes) noexcept
{
  auto buffer = utils::ByteBuffer::create(bytes);

  auto total_read = 0ull;
  while (total_read < bytes) {
    auto res = mTraceeInterface->ReadBytes(addr, bytes - total_read, buffer->next());
    if (!res.success()) {
      return utils::unexpected(NonFullRead{std::move(buffer), static_cast<u32>(bytes - total_read), errno});
    }
    buffer->wrote_bytes(res.bytes_read);
    total_read += res.bytes_read;
  }
  return utils::Expected<std::unique_ptr<utils::ByteBuffer>, NonFullRead>{std::move(buffer)};
}

utils::Expected<std::unique_ptr<utils::ByteBuffer>, NonFullRead>
TraceeController::SafeRead(std::pmr::memory_resource *allocator, AddrPtr addr, u64 bytes) noexcept
{
  auto buffer = utils::ByteBuffer::create(allocator, bytes);

  auto total_read = 0ull;
  while (total_read < bytes) {
    auto res = mTraceeInterface->ReadBytes(addr, bytes - total_read, buffer->next());
    if (!res.success()) {
      return utils::unexpected(NonFullRead{std::move(buffer), static_cast<u32>(bytes - total_read), errno});
    }
    buffer->wrote_bytes(res.bytes_read);
    total_read += res.bytes_read;
  }
  return utils::Expected<std::unique_ptr<utils::ByteBuffer>, NonFullRead>{std::move(buffer)};
}

utils::StaticVector<u8>::OwnPtr
TraceeController::ReadToVector(AddrPtr addr, u64 bytes) noexcept
{
  auto data = std::make_unique<utils::StaticVector<u8>>(bytes);

  auto total_read = 0ull;
  while (total_read < bytes) {
    const auto read_address = addr + total_read;
    const auto result =
      mTraceeInterface->ReadBytes(read_address, bytes - total_read, data->data_ptr() + total_read);
    if (!result.success()) {
      PANIC(fmt::format("Failed to proc_fs read from {}", addr));
    }
    total_read += result.bytes_read;
  }
  data->set_size(total_read);
  return data;
}

std::optional<std::string>
TraceeController::ReadString(TraceePointer<char> address) noexcept
{
  std::string result;
  if (address == nullptr) {
    return std::nullopt;
  }
  auto ch = ReadType<char>(address);
  while (ch != 0) {
    result.push_back(ch);
    address += 1;
    ch = ReadType<char>(address);
  }
  if (result.empty()) {
    return std::nullopt;
  }
  return result;
}

sym::Frame
TraceeController::GetCurrentFrame(TaskInfo &task) noexcept
{
  const auto pc = CacheAndGetPcFor(task);
  const auto obj = FindObjectByPc(pc);
  if (obj == nullptr) {
    return sym::Frame{nullptr, task, 0, 0, pc, nullptr};
  }
  auto cus_matching_addr = obj->GetUnitDataFromProgramCounter(pc);

  // TODO(simon): Massive room for optimization here. Make get_cus_from_pc return source units directly
  //  or, just make them searchable by cu (via some hashed lookup in a map or something.)
  for (auto cu : cus_matching_addr) {
    for (auto src : obj->GetObjectFile()->GetCompilationUnits()) {
      if (cu == src->get_dwarf_unit()) {
        if (auto fn = src->get_fn_by_pc(obj->UnrelocateAddress(pc)); fn) {
          return sym::Frame{obj, task, 0, 0, pc, fn};
        }
      }
    }
  }

  if (auto min_sym = obj->SearchMinimalSymbolFunctionInfo(pc); min_sym != nullptr) {
    return sym::Frame{obj, task, 0, 0, pc, min_sym};
  } else {
    return sym::Frame{obj, task, 0, 0, pc, nullptr};
  }
}

sym::UnwinderSymbolFilePair
TraceeController::GetUnwinderUsingPc(AddrPtr pc) noexcept
{
  for (auto &symbol_file : mSymbolFiles) {
    const auto u = symbol_file->GetObjectFile()->GetUnwinder();
    const auto addr_range = u->mAddressRange;
    if (pc > symbol_file->mBaseAddress) {
      const auto unrelocated = symbol_file->UnrelocateAddress(pc);
      if (addr_range.Contains(unrelocated)) {
        return sym::UnwinderSymbolFilePair{u, symbol_file.get()};
      }
    }
  }
  return sym::UnwinderSymbolFilePair{mNullUnwinder, nullptr};
}

void
TraceeController::CacheRegistersFor(TaskInfo &t) noexcept
{
  if (t.cache_dirty) {
    const auto result = mTraceeInterface->ReadRegisters(t);
    ASSERT(result.is_ok(), "Failed to read register file for {}; {}", t.tid, strerror(result.sys_errno));
    t.cache_dirty = false;
    t.rip_dirty = false;
  }
}

tc::TraceeCommandInterface &
TraceeController::GetInterface() noexcept
{
  return *mTraceeInterface;
}

sym::CallStack &
TraceeController::BuildCallFrameStack(TaskInfo &task, CallStackRequest req) noexcept
{
  DBGLOG(core, "stacktrace for {}", task.tid);
  if (!task.call_stack->IsDirty()) {
    return *task.call_stack;
  }
  CacheRegistersFor(task);
  auto &cs_ref = *task.call_stack;

  auto frame_pcs = task.return_addresses(this, req);
  for (const auto &[depth, i] : utils::EnumerateView{frame_pcs}) {
    auto frame_pc = i.as_void();
    auto result = FindFunctionByPc(frame_pc);
    if (!result) {
      DBGLOG(core, "No object file related to pc; abort call frame state building.");
      break;
    }
    auto &[symbol, obj] = result.value();
    const auto id = Tracer::Instance->new_key();
    Tracer::Instance->set_var_context(VariableContext{.tc = this,
                                                      .t = &task,
                                                      .symbol_file = obj,
                                                      .frame_id = id,
                                                      .id = static_cast<u16>(id),
                                                      .type = ContextType::Frame});
    if (symbol) {
      cs_ref.PushFrame(obj, task, depth, id, i.as_void(), symbol);
    } else {
      auto obj = FindObjectByPc(frame_pc);
      auto min_sym = obj->SearchMinimalSymbolFunctionInfo(frame_pc);
      if (min_sym) {
        cs_ref.PushFrame(obj, task, depth, id, i.as_void(), min_sym);
      } else {
        DBGLOG(core, "[stackframe]: WARNING, no frame info for pc {}", i.as_void());
        cs_ref.PushFrame(obj, task, depth, id, i.as_void(), nullptr);
      }
    }
  }
  return cs_ref;
}

SymbolFile *
TraceeController::FindObjectByPc(AddrPtr addr) noexcept
{
  return utils::find_if(mSymbolFiles,
                        [addr](auto &symbol_file) { return symbol_file->ContainsProgramCounter(addr); })
    .transform([](auto iterator) { return iterator->get(); })
    .value_or(nullptr);
}

std::optional<std::pair<sym::FunctionSymbol *, NonNullPtr<SymbolFile>>>
TraceeController::FindFunctionByPc(AddrPtr addr) noexcept
{
  const auto symbolFile = FindObjectByPc(addr);
  if (symbolFile == nullptr) {
    return std::nullopt;
  }

  auto cus_matching_addr = symbolFile->GetUnitDataFromProgramCounter(addr);

  // TODO(simon): Massive room for optimization here. Make get_cus_from_pc return source units directly
  //  or, just make them searchable by cu (via some hashed lookup in a map or something.)
  for (auto cu : cus_matching_addr) {
    for (auto src : symbolFile->GetObjectFile()->GetCompilationUnits()) {
      if (cu == src->get_dwarf_unit()) {
        if (auto fn = src->get_fn_by_pc(symbolFile->UnrelocateAddress(addr)); fn) {
          return std::make_pair(fn, NonNull(*symbolFile));
        }
      }
    }
  }

  return std::make_pair(nullptr, NonNull(*symbolFile));
}

utils::Expected<u8, BpErr>
TraceeController::InstallSoftwareBreakpointLocation(AddrPtr addr) noexcept
{
  const auto res = mTraceeInterface->InstallBreakpoint(addr);
  if (!res.is_ok()) {
    return utils::unexpected(BpErr{MemoryError{errno, addr}});
  }

  return static_cast<u8>(res.data);
}

Publisher<void> &
TraceeController::GetPublisher(ObserverType type) noexcept
{
  switch (type) {
  case ObserverType::AllStop:
    return mAllStopPublisher;
  }
  MIDAS_UNREACHABLE
}

void
TraceeController::EmitAllStopped() noexcept
{
  DBGLOG(core, "[all-stopped]: sending registered notifications");
  // all_stopped_observer.send_notifications();
  mAllStopPublisher.emit();
}

bool
TraceeController::IsAllStopped() const noexcept
{
  for (const auto &task : mThreads) {
    if (!task->stop_processed()) {
      return false;
    }
  }
  return true;
}

bool
TraceeController::IsSessionAllStopMode() const noexcept
{
  switch (mInterfaceType) {
  case InterfaceType::Ptrace:
    return false;
  case InterfaceType::GdbRemote:
    return !static_cast<tc::GdbRemoteCommander *>(mTraceeInterface.get())->remote_settings().is_non_stop;
  }
  NEVER("Unknown target interface type");
}

TaskInfo *
TraceeController::SetPendingWaitstatus(TaskWaitResult wait_result) noexcept
{
  const auto tid = wait_result.tid;
  auto task = GetTaskByTid(tid);
  ASSERT(task != nullptr, "couldn't find task {}", tid);
  task->wait_status = wait_result.ws;
  task->tracer_stopped = true;
  task->stop_collected = false;
  return task;
}

tc::ProcessedStopEvent
TraceeController::HandleThreadCreated(TaskInfo *task, const ThreadCreated &e,
                                      const RegisterData &register_data) noexcept
{
  // means this event was produced by a Remote session. Construct the task now
  if (!task) {
    CreateNewTask(e.thread_id, true);
    task = GetTaskByTid(e.thread_id);
    if (!register_data.empty()) {
      ASSERT(*GetInterface().arch_info != nullptr,
             "Passing raw register contents with no architecture description doesn't work.");
      task->StoreToRegisterCache(register_data);
      for (const auto &p : register_data) {
        if (p.first == 16) {
          task->rip_dirty = false;
        }
      }
    }
  }

  const auto evt = new ui::dap::ThreadEvent{ui::dap::ThreadReason::Started, e.thread_id};
  mDebugAdapterClient->post_event(evt);

  return tc::ProcessedStopEvent{true, e.resume_action};
}

tc::ProcessedStopEvent
TraceeController::HandleThreadExited(TaskInfo *task, const ThreadExited &) noexcept
{
  if (!task->exited) {
    mDebugAdapterClient->post_event(new ui::dap::ThreadEvent{ui::dap::ThreadReason::Exited, task->tid});
    task->exited = true;
    task->reaped = !Tracer::Instance->TraceExitConfigured;
    if (Tracer::Instance->TraceExitConfigured) {
      return tc::ProcessedStopEvent{true, tc::ResumeAction{tc::RunType::Continue, tc::ResumeTarget::Task}};
    } else {
      return tc::ProcessedStopEvent{
        !mStopHandler->event_settings.thread_exit_stop,
        tc::ResumeAction{tc::RunType::Continue, tc::ResumeTarget::AllNonRunningInProcess}};
    }
  } else {
    ASSERT(!task->reaped, "Expected task to not have been reaped");
    task->reaped = true;
    return tc::ProcessedStopEvent{
      !mStopHandler->event_settings.thread_exit_stop,
      tc::ResumeAction{tc::RunType::Continue, tc::ResumeTarget::AllNonRunningInProcess}};
  }
}

tc::ProcessedStopEvent
TraceeController::HandleProcessExit(const ProcessExited &evt) noexcept
{
  auto t = GetTaskByTid(evt.thread_id);
  if (!t->exited) {
    mDebugAdapterClient->post_event(new ui::dap::ThreadEvent{ui::dap::ThreadReason::Exited, t->tid});
    t->exited = true;
  }
  t->reaped = true;
  mDebugAdapterClient->post_event(new ui::dap::ExitedEvent{evt.exit_code});
  mDebugAdapterClient->post_event(new ui::dap::TerminatedEvent{});
  GetInterface().PerformShutdown();
  mUserBreakpoints.on_exit();
  return tc::ProcessedStopEvent::ProcessExited();
}

tc::ProcessedStopEvent
TraceeController::HandleFork(const ForkEvent &evt) noexcept
{
  auto interface = mTraceeInterface->OnFork(evt.child_pid);
  auto new_supervisor = Tracer::Instance->new_supervisor(Fork(std::move(interface)));
  auto client = ui::dap::DebugAdapterClient::createSocketConnection(mDebugAdapterClient);
  Tracer::Instance->dap->new_client({client});
  client->client_configured(new_supervisor);
  // the new process space copies the old one; which contains breakpoints.
  // we restore the newly forked process space to the real contents. New breakpoints will be set
  // by the initialize -> configDone sequence
  auto &supervisor = new_supervisor->GetInterface();
  for (auto &user : mUserBreakpoints.all_users()) {
    if (auto loc = user->bp_location(); loc) {
      supervisor.DisableBreakpoint(*loc);
    }
  }
  return tc::ProcessedStopEvent{true, {}};
}

tc::ProcessedStopEvent
TraceeController::HandleClone(const Clone &evt) noexcept
{
  auto task = Tracer::Instance->TakeUninitializedTask(evt.child_tid);
  DBGLOG(core, "Running clone handler for {}: child created = {}. Already created: {}", evt.thread_id,
         evt.child_tid, task == nullptr);
  if (!task) {
    CreateNewTask(evt.child_tid, true);
    if (evt.vm_info) {
      SetTaskVmInfo(evt.child_tid, evt.vm_info.value());
    }
  } else {
    task->InitializeThread(GetInterface(), true);
  }
  return tc::ProcessedStopEvent{!mStopHandler->event_settings.clone_stop, {}};
}

ui::dap::DebugAdapterClient *
TraceeController::GetDebugAdapterProtocolClient() const noexcept
{
  return mDebugAdapterClient;
}