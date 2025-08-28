/** LICENSE TEMPLATE */
#pragma once

#include <common/formatter.h>
#include <common/typedefs.h>
#include <memory_resource>

namespace mdb {
struct HelpMessage
{
  std::string_view mInfo{};

  constexpr HelpMessage() noexcept = default;
  constexpr HelpMessage(std::string_view message) noexcept : mInfo(message) {}
  constexpr HelpMessage(const char *message) noexcept : mInfo(message) {}
  template <StringLiteral String> constexpr HelpMessage() noexcept : mInfo(String.StringView()) {}

  template <PushBackContainer ContainerType>
  void
  CreateLinesOfWidth(ContainerType &outResult, size_t width) const noexcept
  {
    size_t lastWordBoundary = 0;
    auto txt = mInfo;
    i64 i = 0;

    const auto processPrefix = [&](auto prefixLen, bool recordLine) noexcept {
      if (recordLine) {
        outResult.push_back(txt.substr(0, prefixLen));
      }
      // we reset these, because we "eat" the string, crawling the head pointer along,
      // making char* head always be at pos = 0
      txt.remove_prefix(prefixLen);
      // i will ++ at end of loop => 0
      i = -1;
      lastWordBoundary = 0;
    };

    for (; i < static_cast<int64_t>(txt.size()); ++i) {
      lastWordBoundary = std::isspace(txt[i]) ? i : lastWordBoundary;
      if (txt[i] == '\n') {
        if (i == 0) {
          processPrefix(1, false);
          continue;
        }
        const auto subLength = (lastWordBoundary == 0 ? i : lastWordBoundary);
        processPrefix(subLength, true);
        // We are creating artificial lines. Don't record the '\n' in the string_views
        processPrefix(1, false);
        continue;
      }
      if (i == static_cast<i64>(width)) {
        // if we have a long string of text that spans multiple lines, we must split it.
        const auto subLength = lastWordBoundary == 0 ? width : lastWordBoundary;
        processPrefix(subLength, true);
      }
    }
    if (!txt.empty()) {
      outResult.push_back(txt);
    }
  }

  constexpr std::vector<std::string_view>
  CreateLinesOfWidth(size_t width) const noexcept
  {
    std::vector<std::string_view> result;
    CreateLinesOfWidth(result, width);
    return result;
  }

  constexpr std::pmr::vector<std::string_view>
  CreateLinesOfWidth(std::pmr::memory_resource *memoryResource, size_t width) const noexcept
  {
    std::pmr::vector<std::string_view> result{ memoryResource };
    CreateLinesOfWidth(result, width);
    return result;
  }
};

} // namespace mdb

namespace mdb::cfg {
class ArgIterator;
}

// N.B. Seeing as how MDB is designed as DAP-first, I am not sure "commands" in the historical sense makes much
// sense, as there's probably not going to be many of them (if even more than 1, ever! We'll see.)
namespace mdb::cmd {

struct ICommand
{
  std::string_view mLongName;
  std::string_view mShortName;
  HelpMessage mHelpMessage;
  virtual void Exec(mdb::cfg::ArgIterator &it) noexcept = 0;
  virtual ~ICommand() noexcept = default;
  const std::string_view
  Name() const noexcept
  {
    if (mLongName.starts_with("--")) {
      return mLongName.substr(2);
    }
    return mLongName;
  }
};

template <typename Fn> struct LambdaCommand final : public ICommand
{
  Fn mLambda;

  LambdaCommand() = delete;
  LambdaCommand(const LambdaCommand &) = delete;
  LambdaCommand &operator=(const LambdaCommand &) = delete;
  LambdaCommand(LambdaCommand &&rhs) noexcept = default;
  LambdaCommand &operator=(LambdaCommand &&rhs) noexcept = default;

  constexpr LambdaCommand(Fn &&lambda) noexcept : mLambda(std::move(lambda)) {}
  ~LambdaCommand() noexcept final = default;

  void
  Exec(mdb::cfg::ArgIterator &it) noexcept final
  {
    mLambda(it);
  }
};
} // namespace mdb::cmd