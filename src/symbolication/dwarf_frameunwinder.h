#pragma once
#include "../common.h"
#include "block.h"
#include "dwarf_defs.h"
#include "utils/immutable.h"
#include <cstdint>

struct ElfSection;
struct ObjectFile;
struct TraceeController;
struct TaskInfo;
class DwarfBinaryReader;
class Elf;

namespace sym {

struct UnwindInfo;

static constexpr auto TOP2_BITS = 0xC0;
static constexpr auto BOTTOM6_BITS = 0x3f;

enum class RegisterRule : u8
{
  Undefined = 0,   // Not able to to recover register value
  SameValue,       // No change
  Offset,          // Previous value of register is stored at address CFA + N
  ValueOffset,     // Previous value of register is the value of CFA + N
  Register,        // Previous value of register, is stored in another register
  Expression,      // DWARF Expression that points to an address where the register value is located
  ValueExpression, // DWARF Expression that produces the value of the register
  ArchSpecific
};

struct Reg
{
  Reg() noexcept;
  union
  {
    u64 value;
    i64 offset;
    std::span<const u8> expr;
  };
  void set_expression(std::span<const u8> expr) noexcept;
  void set_val_expression(std::span<const u8> expr) noexcept;
  void set_offset(i64 offset) noexcept;
  void set_value_offset(i64 val_offset) noexcept;
  void set_register(u64 reg) noexcept;
  RegisterRule rule;
};

struct CFA
{
  bool is_expr;
  union
  {
    struct
    {
      u64 number;
      i64 offset;
    } reg;
    std::span<const u8> expr;
  };

  void set_register(u64 number, i64 offset) noexcept;
  void set_register(u64 number) noexcept;
  void set_offset(i64 offset) noexcept;
  void set_expression(std::span<const u8> expr) noexcept;
};

template <size_t RegCount> struct FrameRegisters
{
  static constexpr auto RSP = 7;
  // initialize `FrameRegisters` with TaskInfo's register contents
  explicit FrameRegisters(TaskInfo *t) noexcept;

  std::array<u64, RegCount> regs;
};

using Registers = std::array<Reg, 17>;
using RegisterValues = std::array<u64, 17>;

class CFAStateMachine
{
  friend int decode(DwarfBinaryReader &reader, CFAStateMachine &state, const UnwindInfo *cfi);

public:
  CFAStateMachine(TraceeController &tc, TaskInfo &task, const UnwindInfo *cfi, AddrPtr pc) noexcept;

  CFAStateMachine(TraceeController &tc, TaskInfo &task, const RegisterValues &frame_below, const UnwindInfo *cfi,
                  AddrPtr pc) noexcept;
  /* Initialization routine for the statemachine - it saves the current task register into the state machine
   * registers. */
  static CFAStateMachine Init(TraceeController &tc, TaskInfo &task, const UnwindInfo *cfi, AddrPtr pc) noexcept;
  u64 compute_expression(std::span<const u8> bytes) noexcept;
  // Reads the register rule of `reg_number` and resolves it's saved (or live, if it hasn't been modified / stored
  // somewhere in memory) contents
  u64 resolve_reg_contents(u64 reg_number, const RegisterValues &reg) noexcept;
  RegisterValues resolve_frame_regs(const RegisterValues &reg) noexcept;
  const CFA &get_cfa() const noexcept;
  const Registers &get_regs() const noexcept;
  const Reg &ret_reg() const noexcept;
  void reset(const UnwindInfo *inf, const RegisterValues &frame_below, AddrPtr pc) noexcept;

private:
  TraceeController &tc;
  TaskInfo &task;
  AddrPtr fde_pc;
  AddrPtr end_pc;
  CFA cfa;
  Registers rule_table;
  u64 cfa_value;
};

struct ByteCodeInterpreter
{
  ByteCodeInterpreter(std::span<const u8> stream) noexcept;
  std::vector<DwarfCallFrame> debug_parse();

  void advance_loc(u64 delta) noexcept;

  std::span<const u8> byte_stream;
};

struct Enc
{
  DwarfExceptionHeaderApplication loc_fmt;
  DwarfExceptionHeaderEncoding value_fmt;
};

struct CommonInformationEntry
{
  u64 length;
  DwFormat fmt;
  Enc fde_encoding;
  u8 addr_size;
  u8 segment_size;
  u8 version;
  u64 id;
  std::optional<std::string_view> augmentation_string;
  AddrPtr personality_address;
  Enc lsda_encoding;
  DwarfExceptionHeaderApplication p_application;
  u64 code_alignment_factor;
  i64 data_alignment_factor;
  u64 retaddr_register;
  std::span<const u8> instructions;
  u64 offset;
};

using CIE = CommonInformationEntry;

struct FrameDescriptionEntry
{
  u64 length;
  u64 cie_offset;
  u64 address_range;
  std::span<u8> instructions;
  u16 padding;
};
using FDE = FrameDescriptionEntry;

/** Structure describing where to find unwind info */
struct UnwindInfo
{
  AddrPtr start;
  AddrPtr end;
  u8 code_align;
  i8 data_align;
  u8 aug_data_len;
  AddrPtr lsda;
  CIE *cie;
  std::span<const u8> fde_insts{};
};

class Unwinder
{
public:
  Unwinder(ObjectFile *objfile) noexcept;
  u64 total_cies() const noexcept;
  u64 total_fdes() const noexcept;

  // Sets `low` to `ptr` _iff_ ptr is lower than current low.
  void set_low(AddrPtr ptr) noexcept;
  // Sets `high` to `ptr` _iff_ ptr is higher than current high.
  void set_high(AddrPtr ptr) noexcept;
  const UnwindInfo *get_unwind_info(AddrPtr pc) const noexcept;

  // Objfile
  ObjectFile *objfile;
  AddressRange addr_range;
  // .debug_frame
  std::vector<CIE> dwarf_debug_cies;
  std::vector<UnwindInfo> dwarf_unwind_infos;

  // .eh_frame
  std::vector<CIE> elf_eh_cies;
  std::vector<UnwindInfo> elf_eh_unwind_infos;
};

class UnwindIterator
{
public:
  UnwindIterator(TraceeController *tc, AddrPtr first_pc) noexcept;
  const UnwindInfo *get_info(AddrPtr pc) noexcept;
  bool is_null() const noexcept;

private:
  TraceeController *tc;
  Unwinder *current;
};

std::pair<u64, u64> elf_eh_calculate_entries_count(DwarfBinaryReader reader) noexcept;
std::pair<u64, u64> dwarf_eh_calculate_entries_count(DwarfBinaryReader reader) noexcept;
CommonInformationEntry read_cie(u64 length, u64 cie_offset, DwarfBinaryReader &reader) noexcept;
std::unique_ptr<Unwinder> parse_eh(ObjectFile *objfile, const ElfSection *eh_frame, AddrPtr base_vma) noexcept;
void parse_dwarf_eh(const Elf *elf, Unwinder *unwinder_db, const ElfSection *debug_frame, int fde_count) noexcept;

FrameDescriptionEntry read_fde(DwarfBinaryReader &reader);

int decode(DwarfBinaryReader &reader, CFAStateMachine &state, const UnwindInfo *cfi);

} // namespace sym