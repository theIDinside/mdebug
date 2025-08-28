/** LICENSE TEMPLATE */
#pragma once

// mdb
#include "utils/format_utils.h"
#include "utils/util.h"
#include <common.h>
#include <common/formatter.h>
#include <common/typedefs.h>
#include <expected>
#include <filesystem>
#include <sys/ioctl.h>
#include <type_traits>
#include <utils/algorithm.h>
#include <utils/command.h>
// std
#include <charconv>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_set>
#include <vector>

using namespace std::string_view_literals;

#define TRY_ARG_VAL(value, reader, arg)                                                                           \
  auto value = reader.NextArgIfValue(arg);                                                                        \
  if (!value) {                                                                                                   \
    return std::unexpected(ParseError::MissingArgValue);                                                          \
  }

namespace mdb::cfg {

struct Ok
{
};

#define FOR_CLI_EACH_PARSE_ERROR(MAKE_ERR)                                                                        \
  MAKE_ERR(None, "Error not set.")                                                                                \
  MAKE_ERR(ArgNotFound, "Argument not found.")                                                                    \
  MAKE_ERR(MissingArgValue, "Command line option is missing it's value.")                                         \
  MAKE_ERR(InvalidFormat, "Invalid format of argument.")                                                          \
  MAKE_ERR(OptionIsNotFlag, "Option is not a flag.")                                                              \
  MAKE_ERR(AccessingInvalidType, "Invalid underlying type.")                                                      \
  MAKE_ERR(UnrecognizedArgument, "Argument is not a recognized option or command.")                               \
  MAKE_ERR(SocketPathNotAllowed, "Unix Socket path is not allowed: root directory must be /tmp")                  \
  MAKE_ERR(DirectoryDoesNotExist, "Directory does not exist")                                                     \
  MAKE_ERR(DebugAdapterSocketPathAlreadyTaken,                                                                    \
    "Socket intended for communication using the debug adapter protocol already in use.")

enum class ParseErrorType : u8
{
  FOR_CLI_EACH_PARSE_ERROR(DEFAULT_ENUM)
};

struct ParseOk
{
};

struct ParserError
{
  ParseErrorType mError;
  std::vector<std::string_view> mInputs;

  operator std::unexpected<ParserError>() && noexcept { return std::unexpected<ParserError>(std::move(*this)); }
};

template <typename T> using ParseResult = std::expected<T, ParserError>;

template <typename T, typename U = T>
  requires(std::is_convertible_v<U, T>)
static std::expected<T, ParserError>
Ok(U &&value)
{
  return std::expected<T, ParserError>{ T{ std::move(value) } };
}

template <ParseErrorType Type>
static constexpr std::unexpected<ParserError>
Error(std::vector<std::string_view> inputs) noexcept
{
  return ParserError{ Type, std::move(inputs) };
}

class ArgIterator
{
public:
  constexpr ArgIterator(int argc, const char **argv) : mArgCount(argc), mArgs(argv) {}

  bool
  HasNext() const noexcept
  {
    return mIndex < mArgCount;
  }

  // Called at the beginning of the start of the "next parse pass", which may contain 0 or N arguments from the
  // argument vector. It's called, as the very first thing, in each iteration in Parse in CommandLineRegistry.
  // Prior to it, it should always be checked HasNextValue()
  std::string_view
  BeginNext() noexcept
  {
    RememberPosition();
    return *GetNext();
  }

  std::optional<std::string_view>
  GetNext() noexcept
  {
    if (mInsideInlineArgument) {
      std::string_view value = mArgs[mIndex];
      value.remove_prefix(mInsideInlineArgument.value());
      mInsideInlineArgument = {};
      ++mIndex;
      return value;
    }

    if (!HasNext()) {
      return std::nullopt;
    }
    std::string_view value = mArgs[mIndex];
    auto inlineValuePos = value.find_first_of('=');
    if (inlineValuePos != value.npos) {
      mInsideInlineArgument = inlineValuePos + 1;
      return value.substr(0, inlineValuePos);
    } else {
      ++mIndex;
    }
    return value;
  }

  std::span<const char *>
  Args() const noexcept
  {
    return std::span{ mArgs, mArgs + mArgCount };
  }

  std::unexpected<ParserError>
  Error(ParseErrorType type) noexcept
  {
    return std::unexpected(ParserError{ type, GetArgsCurrentlyBeingParsed() });
  }

private:
  std::vector<std::string_view>
  GetArgsCurrentlyBeingParsed()
  {
    // always take the "current one" too, which may only have been partially parsed (due to inline values via
    // foo=bar)
    const auto count = (mIndex - mRememberedIndex);
    std::vector<std::string_view> result;
    CopyTo(Args().subspan(mRememberedIndex, count), result);
    return result;
  }

  // Set before being passed to a parser function, so that the particular parser function
  // does not have to do logic to remember how many arguments its parsed etc. It just needs to say `GetNext()` and
  // then if it wants all arguments it's consumed, it says `GetArgsCurrentlyBeingParsed()`.
  // It's `CommandLineRegister`'s responsibility to push the remember position before handing off the iterator.
  void
  RememberPosition() noexcept
  {
    mRememberedIndex = mIndex;
  }

  int mArgCount;
  const char **mArgs;
  int mIndex{ 1 };
  std::optional<size_t> mInsideInlineArgument{};
  int mRememberedIndex{ 0 };
};

#ifndef TryExpected
#define TryExpected(iterator)                                                                                     \
  ({                                                                                                              \
    auto ___MAYBE_VALUE___ = iterator.GetNext();                                                                  \
    if (!___MAYBE_VALUE___) {                                                                                     \
      return iterator.Error(ParseErrorType::MissingArgValue);                                                     \
    }                                                                                                             \
    *___MAYBE_VALUE___;                                                                                           \
  })
#endif

struct OptionMetadata
{
  std::string mShortName;
  std::string mLongName;
  HelpMessage mInfo;
  bool mIsFlag;
};

template <typename ParseInput> struct IOption : OptionMetadata
{
  using Input = ParseInput;
  virtual std::expected<ParseOk, ParserError> Parse(ParseInput it) noexcept = 0;
  virtual void ApplyDefault() noexcept = 0;
  virtual ~IOption() noexcept = default;
};

template <typename T, typename U, typename ParseInput> class MemberOption : public IOption<ParseInput>
{
  using Data = OptionMetadata;
  using IBase = IOption<ParseInput>;

public:
  using MemberPtr = T U::*;
  using ParserFn = ParseResult<T> (*)(typename IBase::Input &);

  MemberOption(std::string_view shortName,
    std::string_view longName,
    HelpMessage helpMessage,
    MemberPtr memberPointer,
    U *object,
    ParserFn parser,
    T defaultValue)
      : mMemberPointer(memberPointer), mObject(object), mParseFn(parser), mDefault(std::move(defaultValue))
  {
    Data::mShortName = shortName;
    Data::mLongName = longName;
    Data::mInfo = helpMessage;
    Data::mIsFlag = std::is_same_v<T, bool>;
  }

  std::expected<ParseOk, ParserError>
  Parse(ParseInput it) noexcept override
  {
    auto result = mParseFn(it);
    if (!result) {
      return std::unexpected(result.error());
    }
    (*mObject).*mMemberPointer = std::move(result.mValue);
    return ParseOk{};
  }

  void
  ApplyDefault() noexcept override
  {
    (*mObject).*mMemberPointer = mDefault;
  }

private:
  MemberPtr mMemberPointer;
  U *mObject;
  ParserFn mParseFn;
  T mDefault;
};

template <typename T, typename ParseInput> class DirectOption : public IOption<ParseInput>
{
  using Data = OptionMetadata;
  using IBase = IOption<ParseInput>;

public:
  using ParserFn = ParseResult<T> (*)(typename IBase::Input &);

  DirectOption(std::string_view shortName,
    std::string_view longName,
    HelpMessage helpMessage,
    T &reference,
    ParserFn parser,
    T defaultValue)
      : mReference(&reference), mParseFn(parser), mDefault(std::move(defaultValue))
  {
    Data::mShortName = shortName;
    Data::mLongName = longName;
    Data::mInfo = helpMessage;
    Data::mIsFlag = std::is_same_v<T, bool>;
  }

  std::expected<ParseOk, ParserError>
  Parse(ParseInput it) noexcept override
  {
    auto result = mParseFn(it);
    if (!result) {
      return std::unexpected(std::move(result.error()));
    }
    *mReference = std::move(result.value());
    return ParseOk{};
  }

  void
  ApplyDefault() noexcept override
  {
    *mReference = mDefault;
  }

private:
  T *mReference;
  ParserFn mParseFn;
  T mDefault;
};

struct CommandLineResult
{
  std::vector<ParserError> mErrors;
};

class CommandLineRegistry
{
  static constexpr auto UNIFORM_LINE_INDENT = 2;
  std::unordered_map<std::string_view, std::shared_ptr<IOption<ArgIterator &>>> mOptions;
  std::unordered_map<std::string_view, std::shared_ptr<IOption<std::string_view>>> mEnvironmentVariables;
  std::unordered_map<std::string_view, std::shared_ptr<cmd::ICommand>> mCommands;
  // Holds the length of the largest left-column when displaying using PrintHelp
  // so the left column contains "-c, --com <value>" for an option that has both long and short form and is not a
  // flag. By calculating max width, we can format "properly", when we can't access a terminal size.
  size_t mLeftColumnDisplayWidth{ 0 };
  bool mParseCompleted{ false };

  void
  AssertUnique(std::string_view shortName, std::string_view longName) noexcept
  {
    VERIFY(!shortName.empty() || !longName.empty(), "You've not given this option/command a name!");
    if (!longName.empty()) {
      VERIFY(mOptions.count(longName) == 0, "Already added option {}", longName);
      VERIFY(mCommands.count(longName) == 0, "Already added command {}", longName);
    }

    if (!shortName.empty()) {
      VERIFY(mOptions.count(shortName) == 0, "Already added option {}", shortName);
      VERIFY(mCommands.count(shortName) == 0, "Already added command {}", shortName);
    }
  }

  void
  UpdateLeftColumnWidth(bool isFlag, std::string_view shortName, std::string_view longName) noexcept
  {
    const auto leftColumnWidth =
      shortName.size() + longName.size() + (isFlag ? 0 : " <value> "sv.size()) + UNIFORM_LINE_INDENT;

    mLeftColumnDisplayWidth = std::max(mLeftColumnDisplayWidth, leftColumnWidth);
  }

  template <typename T>
  auto &
  MapFor(this auto &&self)
  {
    static_assert(std::is_base_of_v<IOption<ArgIterator &>, T> ||
                    std::is_base_of_v<IOption<std::string_view>, T> || std::is_base_of_v<cmd::ICommand, T>,
      "T must be derived from BaseOption or cmd::ICommand");

    if constexpr (std::is_base_of_v<IOption<ArgIterator &>, T>) {
      return self.mOptions;
    } else if constexpr (std::is_base_of_v<IOption<std::string_view>, T>) {
      return self.mEnvironmentVariables;
    } else {
      return self.mCommands;
    }
  }

  template <typename T>
  void
  AddOption(std::string_view shortName, std::string_view longName, std::shared_ptr<T> &&item) noexcept
  {
    VERIFY(!mParseCompleted, "You are adding options after parse has completed.");
    AssertUnique(shortName, longName);
    auto &map = MapFor<T>();
    std::shared_ptr<T> ptr{ std::move(item) };
    if (!shortName.empty()) {
      map.emplace(shortName, ptr);
    }

    if (!longName.empty()) {
      map.emplace(longName, std::move(ptr));
    }
  }

  template <typename T>
  void
  AddEnvironmentVariable(std::string_view name, std::shared_ptr<T> &&item) noexcept
  {
    VERIFY(!mParseCompleted, "You are adding options after parse has completed.");
    VERIFY(mEnvironmentVariables.count(name) == 0, "Environment variable option already configured.");
    auto &map = MapFor<T>();
    map.emplace(name, std::move(item));
  }

  template <typename T>
  constexpr std::vector<std::shared_ptr<T>>
  GetAllOf(this auto &&self) noexcept
  {
    auto &map = self.template MapFor<T>();
    std::vector<std::shared_ptr<T>> result;
    result.reserve(map.size());

    std::unordered_set<void *> taken{};

    for (const auto &[k, v] : map) {
      if (!taken.contains((void *)v.get())) {
        result.push_back(v);
        taken.insert((void *)v.get());
      }
    }
    return result;
  }

public:
  static constexpr auto kValuePlaceHolder = " <value> "sv;

  std::vector<std::shared_ptr<IOption<std::string_view>>>
  GetEnvironmentVariableOptions(this auto &&self) noexcept
  {
    std::vector<std::shared_ptr<IOption<std::string_view>>> result;
    result.reserve(self.mEnvironmentVariables.size());
    for (const auto &[k, v] : self.mEnvironmentVariables) {
      result.push_back(v);
    }
    return result;
  }

  std::vector<std::shared_ptr<IOption<ArgIterator &>>>
  GetOptions(this auto &&self) noexcept
  {
    return self.template GetAllOf<IOption<ArgIterator &>>();
  }

  std::vector<std::shared_ptr<cmd::ICommand>>
  GetCommands(this auto &&self) noexcept
  {
    return self.template GetAllOf<cmd::ICommand>();
  }

  // AddCommand for lambdas
  template <typename Fn>
  void
  AddLambdaCommand(std::string_view shortName, std::string_view longName, std::string_view help, Fn func) noexcept
  {
    auto cmd = std::make_shared<cmd::LambdaCommand<Fn>>(cmd::LambdaCommand<Fn>{ std::move(func) });
    cmd->mLongName = longName;
    cmd->mShortName = shortName;
    cmd->mHelpMessage = help;

    AddOption(shortName, longName, std::move(cmd));
  }

  // Commands that don't take a [](auto inputTypeVal) { /* do stuff */ } and have their explicit behavior
  // implemented by Exec() instead.
  template <typename CommandType, typename... Args>
  void
  AddCommand(std::string_view shortName, std::string_view longName, std::string_view help, Args... args) noexcept
  {
    auto cmd = std::make_shared<CommandType>(std::forward<Args>(args)...);
    cmd->mLongName = longName;
    cmd->mShortName = shortName;
    cmd->mHelpMessage = help;

    AddOption(shortName, longName, std::move(cmd));
  }

  template <typename ParseInput, typename T, typename U, typename ConvertibleToT>
  void
  AddOption(std::string_view shortName,
    std::string_view longName,
    HelpMessage message,
    T U::*member,
    U *object,
    typename MemberOption<T, U, ParseInput>::ParserFn parser,
    ConvertibleToT &&defaultVal) noexcept
    requires std::is_convertible_v<ConvertibleToT, T>
  {
    UpdateLeftColumnWidth(std::is_same_v<T, bool>, shortName, longName);

    auto opt = std::make_shared<MemberOption<T, U, ParseInput>>(
      shortName, longName, message, member, object, parser, T{ std::move(defaultVal) });

    AddOption(shortName, longName, std::move(opt));
  }

  template <typename ParseInput, typename T, typename ConvertibleToT>
  void
  AddOption(std::string_view shortName,
    std::string_view longName,
    HelpMessage message,
    T &variable,
    typename DirectOption<T, ParseInput>::ParserFn parser,
    ConvertibleToT defaultVal) noexcept
    requires(std::is_convertible_v<ConvertibleToT, T>)
  {
    UpdateLeftColumnWidth(std::is_same_v<T, bool>, shortName, longName);

    auto opt = std::make_shared<DirectOption<T, ParseInput>>(
      shortName, longName, message, variable, parser, std::move(defaultVal));

    AddOption(shortName, longName, std::move(opt));
  }

  template <typename T, typename U, typename ConvertibleToT>
  void
  AddEnvironmentVariable(std::string_view name,
    HelpMessage message,
    T U::*member,
    U *object,
    typename MemberOption<T, U, std::string_view>::ParserFn parser,
    ConvertibleToT &&defaultVal) noexcept
    requires std::is_convertible_v<ConvertibleToT, T>
  {
    // TODO: Change this interface perhaps, environment variable options have their shortName = "" (none)
    UpdateLeftColumnWidth(/* isFlag */ false, "", name);

    auto opt = std::make_shared<MemberOption<T, U, std::string_view>>(
      "", name, message, member, object, parser, T{ std::move(defaultVal) });

    AddEnvironmentVariable(name, std::move(opt));
  }

  template <typename T, typename ConvertibleToT = T>
  void
  AddEnvironmentVariable(std::string_view name,
    HelpMessage message,
    T &variable,
    typename DirectOption<T, std::string_view>::ParserFn parser,
    ConvertibleToT defaultVal = T{}) noexcept
    requires(std::is_convertible_v<ConvertibleToT, T>)
  {
    // TODO: Change this interface perhaps, environment variable options have their shortName = "" (none)
    UpdateLeftColumnWidth(/* isFlag */ false, "", name);

    auto opt = std::make_shared<DirectOption<T, std::string_view>>(
      "", name, message, variable, parser, std::move(defaultVal));

    AddEnvironmentVariable(name, std::move(opt));
  }

  CommandLineResult Parse(int argc, const char **argv) noexcept;
  void ParseEnvironmentVariableOptions() noexcept;

  void PrintHelp() const noexcept;
  void PrintHelpAbout(const OptionMetadata &option, u16 leftColumn, u16 rightColumn) const noexcept;
  std::pair<u16, u16> GetTerminalSize() const noexcept;
};

template <typename ResultType> struct FromTraits;

#define NumberTrait(NumberType)                                                                                   \
  template <> struct FromTraits<NumberType>                                                                       \
  {                                                                                                               \
    static ParseResult<NumberType>                                                                                \
    From(ArgIterator &it)                                                                                         \
    {                                                                                                             \
      auto arg = TryExpected(it);                                                                                 \
                                                                                                                  \
      NumberType number;                                                                                          \
      auto [ptr, ec] = std::from_chars(arg.data(), arg.data() + arg.size(), number);                              \
      if (ec == std::errc()) {                                                                                    \
        return number;                                                                                            \
      } else {                                                                                                    \
        return it.Error(ParseErrorType::InvalidFormat);                                                           \
      }                                                                                                           \
    }                                                                                                             \
                                                                                                                  \
    static ParseResult<NumberType>                                                                                \
    From(std::string_view arg) noexcept                                                                           \
    {                                                                                                             \
      if (arg.empty())                                                                                            \
        return std::unexpected(ParserError{ ParseErrorType::MissingArgValue, {} });                               \
      NumberType number;                                                                                          \
      auto [ptr, ec] = std::from_chars(arg.data(), arg.data() + arg.size(), number);                              \
      if (ec == std::errc()) {                                                                                    \
        return number;                                                                                            \
      } else {                                                                                                    \
        return std::unexpected(mdb::cfg::ParserError{ ParseErrorType::InvalidFormat, { arg } });                  \
      }                                                                                                           \
    }                                                                                                             \
  };

#define FOR_EACH_PRIMITIVE(PRIM)                                                                                  \
  PRIM(i32)                                                                                                       \
  PRIM(i64)                                                                                                       \
  PRIM(u32)                                                                                                       \
  PRIM(u64)                                                                                                       \
  PRIM(float)                                                                                                     \
  PRIM(double)

#define AsIsTrait(Type)                                                                                           \
  template <> struct FromTraits<Type>                                                                             \
  {                                                                                                               \
    static ParseResult<Type>                                                                                      \
    From(std::string_view arg) noexcept                                                                           \
    {                                                                                                             \
      return Type{ arg };                                                                                         \
    }                                                                                                             \
  };

#define FOR_EACH_AS_IS(AS_IS)                                                                                     \
  AS_IS(std::string_view)                                                                                         \
  AS_IS(std::filesystem::path)

FOR_EACH_AS_IS(AsIsTrait)

FOR_EACH_PRIMITIVE(NumberTrait);

} // namespace mdb::cfg

template <> struct std::formatter<mdb::cfg::ParseErrorType>
{
  BASIC_PARSE

  template <typename FormatContext>
  constexpr auto
  format(const mdb::cfg::ParseErrorType &option, FormatContext &context) const noexcept
  {
#define PARSE_ERROR_MSG(EnumValue, Message, ...)                                                                  \
  case mdb::cfg::ParseErrorType::EnumValue:                                                                       \
    return std::format_to(context.out(), Message);

    switch (option) {
      FOR_CLI_EACH_PARSE_ERROR(PARSE_ERROR_MSG)
    }
#undef PARSE_ERROR_MSG
  }
};

template <typename T> struct UsagePrintFormatting
{
  using Type = T;
  const T &mValue;
  const std::uint16_t mLeftColumnWidth{ 20 };
  const std::uint16_t mRightColumnWidth{ 80 };

  [[gnu::returns_nonnull]] constexpr auto
  operator->(this auto &&self) noexcept -> decltype(&self.mValue)
  {
    return &self.mValue;
  }
};

template <> struct std::formatter<mdb::cfg::OptionMetadata>
{
  BASIC_PARSE

  template <typename FormatContext>
  constexpr auto
  format(const mdb::cfg::OptionMetadata &option, FormatContext &context) const noexcept
  {
    auto it =
      std::format_to(context.out(), "short form: {}\n", option.mShortName.empty() ? "none" : option.mShortName);

    return std::format_to(context.out(),
      "long form: {}\nhelp message:\n{}",
      option.mLongName.empty() ? "none" : option.mLongName,
      option.mInfo);
  }
};

template <> struct std::formatter<UsagePrintFormatting<mdb::cfg::OptionMetadata>>
{
  BASIC_PARSE

  template <typename FormatContext>
  constexpr auto
  format(const UsagePrintFormatting<mdb::cfg::OptionMetadata> &option, FormatContext &context) const noexcept
  {
    auto columnSpaceLeft = option.mLeftColumnWidth;
    auto it = std::format_to(context.out(), "  ");
    columnSpaceLeft -= 2;
    const auto &opt = option.mValue;

    if (!opt.mShortName.empty()) {
      it = std::format_to(it, "{}, ", opt.mShortName);
      columnSpaceLeft -= (opt.mShortName.size() + 2);
    }

    if (!opt.mLongName.empty()) {
      columnSpaceLeft -= opt.mLongName.size();
      it = std::format_to(it, "{}", opt.mLongName);
    }

    if (!opt.mIsFlag) {
      columnSpaceLeft -= mdb::cfg::CommandLineRegistry::kValuePlaceHolder.size();
      it = std::format_to(it, " <value> {:>{}}", "", columnSpaceLeft + 1);
    }
    auto lines = opt.mInfo.CreateLinesOfWidth(option.mRightColumnWidth);
    auto span = std::span{ lines };
    for (const auto &line : span.subspan(0, 1)) {
      it = std::format_to(it, "{}\n", line);
    }

    for (const auto &line : span.subspan(1)) {
      it = std::format_to(it, "{:<{}}{}\n", "", option.mLeftColumnWidth, line);
    }
    return it;
  }
};

template <> struct std::formatter<mdb::cfg::ParserError>
{
  BASIC_PARSE;

  template <typename FormatContext>
  constexpr auto
  format(const mdb::cfg::ParserError &error, FormatContext &ctx) noexcept
  {
    return std::format_to(ctx.out(), "Parse error: {}", error.mError);
  }
};

#undef FOR_CLI_EACH_PARSE_ERROR