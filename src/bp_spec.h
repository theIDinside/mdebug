/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common.h>
#include <common/typedefs.h>
#include <utils/format_utils.h>

// std
#include <memory>
#include <optional>
#include <string>

namespace mdb {
enum class DapBreakpointType : u8
{
  source = 0,
  function = 1,
  instruction = 2,
};

struct SourceBreakpointSpec
{
  u32 line;
  std::optional<u32> column;
  std::optional<std::string> log_message;

  [[nodiscard]] constexpr bool
  IsLogPoint() const
  {
    return log_message.has_value();
  }

  // All comparisons assume that this `SourceBreakpoint` actually belongs in the same source file
  // Comparing two `SourceBreakpoint` objects from different source files is non sensical
  friend constexpr auto operator<=>(const SourceBreakpointSpec &l, const SourceBreakpointSpec &r) = default;

  // All comparisons assume that this `SourceBreakpoint` actually belongs in the same source file
  // Comparing two `SourceBreakpoint` objects from different source files is non sensical
  friend constexpr auto
  operator==(const SourceBreakpointSpec &l, const SourceBreakpointSpec &r)
  {
    return l.line == r.line && l.column == r.column && l.log_message == r.log_message;
  }
};

struct SourceBreakpointSpecPair
{
  std::string mFilePath;
  SourceBreakpointSpec mSpec;
};

struct FunctionBreakpointSpec
{
  std::string mName;
  bool mIsRegex;
  friend constexpr auto operator<=>(const FunctionBreakpointSpec &l, const FunctionBreakpointSpec &r) = default;

  friend constexpr auto
  operator==(const FunctionBreakpointSpec &l, const FunctionBreakpointSpec &r)
  {
    return l.mName == r.mName;
  }
};

struct InstructionBreakpointSpec
{
  std::string mInstructionReference;
  friend constexpr auto operator<=>(
    const InstructionBreakpointSpec &l, const InstructionBreakpointSpec &r) = default;
  friend constexpr auto
  operator==(const InstructionBreakpointSpec &l, const InstructionBreakpointSpec &r)
  {
    return l.mInstructionReference == r.mInstructionReference;
  }
};

struct BreakpointSpecification
{
  DapBreakpointType mKind;
  std::optional<std::string> mCondition;
  std::optional<std::string> mHitCondition;
  union
  {
    SourceBreakpointSpecPair *uSource;
    FunctionBreakpointSpec *uFunction;
    InstructionBreakpointSpec *uInstruction;
  };

  friend constexpr auto
  operator==(const BreakpointSpecification &l, const BreakpointSpecification &r) noexcept
  {
    auto compared = l.mKind == r.mKind && l.mCondition == r.mCondition && l.mHitCondition == r.mHitCondition;
    if (compared) {
      switch (l.mKind) {
      case DapBreakpointType::source:
        return (l.uSource->mFilePath == r.uSource->mFilePath && l.uSource->mSpec == r.uSource->mSpec);
      case DapBreakpointType::function:
        return *l.uFunction == *r.uFunction;
      case DapBreakpointType::instruction:
        return *l.uInstruction == *r.uInstruction;
      }
    }
    return false;
  }

private:
  BreakpointSpecification(DapBreakpointType kind,
    std::optional<std::string> condition,
    std::optional<std::string> hitCondition) noexcept;
  void DestroyUnion() noexcept;

public:
  constexpr BreakpointSpecification() noexcept
      : mKind(DapBreakpointType::source), mCondition(), mHitCondition(), uSource(nullptr)
  {
  }
  ~BreakpointSpecification() noexcept;

  BreakpointSpecification(std::optional<std::string> condition,
    std::optional<std::string> hitCondition,
    SourceBreakpointSpecPair *src) noexcept;

  BreakpointSpecification(std::optional<std::string> condition,
    std::optional<std::string> hitCondition,
    FunctionBreakpointSpec *fun) noexcept;

  BreakpointSpecification(std::optional<std::string> condition,
    std::optional<std::string> hitCondition,
    InstructionBreakpointSpec *ins) noexcept;

  BreakpointSpecification(BreakpointSpecification &&moveFrom) noexcept;

  BreakpointSpecification(const BreakpointSpecification &copy) noexcept;

  BreakpointSpecification &operator=(const BreakpointSpecification &copy) noexcept;

  template <typename T>
  static std::unique_ptr<BreakpointSpecification>
  Make(std::optional<std::string> condition, std::optional<std::string> hitCondition, T *spec) noexcept
    requires std::is_same_v<T, SourceBreakpointSpecPair> || std::is_same_v<T, FunctionBreakpointSpec> ||
             std::is_same_v<T, InstructionBreakpointSpec>
  {
    return std::make_unique<BreakpointSpecification>(std::move(condition), std::move(hitCondition), spec);
  }

  template <typename T, typename... Args>
  static BreakpointSpecification
  Create(std::optional<std::string> condition, std::optional<std::string> hitCondition, Args &&...args) noexcept
    requires std::is_same_v<T, SourceBreakpointSpecPair> || std::is_same_v<T, FunctionBreakpointSpec> ||
             std::is_same_v<T, InstructionBreakpointSpec>
  {
    return BreakpointSpecification{
      std::move(condition), std::move(hitCondition), new T{ std::forward<Args>(args)... }
    };
  }

  std::optional<u32> Column() const noexcept;

  std::optional<u32> Line() const noexcept;

private:
  static void TakeVariant(BreakpointSpecification *out, BreakpointSpecification *takeFrom) noexcept;

  static void CloneVariant(BreakpointSpecification *out, const BreakpointSpecification *spec) noexcept;

  static BreakpointSpecification *Clone(const BreakpointSpecification *spec) noexcept;

public:
  std::unique_ptr<BreakpointSpecification> Clone() const noexcept;
};

}; // namespace mdb

template <> struct std::hash<mdb::SourceBreakpointSpec>
{
  using argument_type = mdb::SourceBreakpointSpec;
  using result_type = size_t;

  result_type
  operator()(const argument_type &m) const
  {
    const auto u32_hasher = std::hash<u32>{};

    const auto line_col_hash =
      m.column.transform([&h = u32_hasher, line = m.line](auto col) { return h(col) ^ h(line); })
        .or_else([&h = u32_hasher, line = m.line]() { return std::optional{ h(line) }; })
        .value();

    if (m.log_message) {
      return line_col_hash ^ std::hash<std::string_view>{}(m.log_message.value());
    }
    return line_col_hash;
  }
};

template <> struct std::hash<mdb::FunctionBreakpointSpec>
{
  using argument_type = mdb::FunctionBreakpointSpec;
  using result_type = size_t;

  result_type
  operator()(const argument_type &m) const
  {
    return std::hash<std::string_view>{}(m.mName);
  }
};

template <> struct std::hash<mdb::InstructionBreakpointSpec>
{
  using argument_type = mdb::InstructionBreakpointSpec;
  using result_type = size_t;

  result_type
  operator()(const argument_type &m) const
  {
    return std::hash<std::string_view>{}(m.mInstructionReference);
  }
};

template <> struct std::hash<mdb::BreakpointSpecification>
{
  using argument_type = mdb::BreakpointSpecification;
  using result_type = size_t;

  result_type operator()(const argument_type &m) const noexcept;
};

template <> struct std::formatter<mdb::SourceBreakpointSpecPair>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const mdb::SourceBreakpointSpecPair &source_spec, FormatContext &ctx) const
  {

    auto out = std::format_to(ctx.out(), R"(Source = {}:{})", source_spec.mFilePath, source_spec.mSpec.line);
    if (source_spec.mSpec.column) {
      out = std::format_to(out, R"(:{})", *source_spec.mSpec.column);
    }

    if (source_spec.mSpec.log_message) {
      out = std::format_to(out, R"( and a evaluated log message)", *source_spec.mSpec.log_message);
    }

    return out;
  }
};

template <> struct std::formatter<mdb::FunctionBreakpointSpec>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const mdb::FunctionBreakpointSpec &spec, FormatContext &ctx) const
  {
    const auto &[name, regex] = spec;
    auto out = std::format_to(ctx.out(), R"(Function={}, searched using regex={})", name, regex);

    return out;
  }
};

template <> struct std::formatter<mdb::InstructionBreakpointSpec>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const mdb::InstructionBreakpointSpec &spec, FormatContext &ctx) const
  {
    const auto &[insReference] = spec;
    auto out = std::format_to(ctx.out(), R"(Instruction Address={})", insReference);

    return out;
  }
};

template <> struct std::formatter<mdb::BreakpointSpecification>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const mdb::BreakpointSpecification &spec, FormatContext &ctx) const
  {
    auto iterator = ctx.out();
    using enum mdb::DapBreakpointType;
    switch (spec.mKind) {
    case source:
      iterator = std::format_to(iterator, "{}", *spec.uSource);
      break;
    case function:
      iterator = std::format_to(iterator, "{}", *spec.uFunction);
      break;
    case instruction:
      iterator = std::format_to(iterator, "{}", *spec.uInstruction);
      break;
    }

    if (spec.mCondition) {
      return FormatEscaped(iterator, std::format(R"(, with hit condition = "{}")", *spec.mCondition));
    }

    return iterator;
  }
};