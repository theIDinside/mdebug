/** LICENSE TEMPLATE */
#include "command_line.h"
#include <common/formatter.h>

// mdb
#include <common.h>

#include <events/event.h>
#include <utils/logger.h>

// std
#include <print>

// system
#include <sys/ioctl.h>
#include <unistd.h>

namespace mdb::cfg {
CommandLineResult
CommandLineRegistry::Parse(int argc, const char **argv) noexcept
{
  CommandLineResult result{};

  result.mErrors.reserve(argc - 1);
  for (auto &opt : GetOptions()) {
    opt->ApplyDefault();
  }
  ArgIterator it(argc, argv);
  while (it.HasNext()) {
    auto current = it.BeginNext();

    if (auto optionIter = mOptions.find(current); optionIter != std::end(mOptions)) {
      auto res = optionIter->second->Parse(it);
      if (!res) {
        result.mErrors.push_back(std::move(res.error()));
      }
    } else if (auto cmdIter = mCommands.find(current); cmdIter != std::end(mCommands)) {
      cmdIter->second->Exec(it);
    } else {
      result.mErrors.push_back(it.Error(ParseErrorType::UnrecognizedArgument).error());
    }
  }

  // Environment variables fail silently, because they're not intended to be "hard options".
  ParseEnvironmentVariableOptions();
  return result;
}

void
CommandLineRegistry::ParseEnvironmentVariableOptions() noexcept
{
  for (auto &opt : GetEnvironmentVariableOptions()) {
    opt->ApplyDefault();
  }

  for (const auto &[k, v] : mEnvironmentVariables) {
    if (auto value = getenv(k.data()); value) {
      v->Parse(std::string_view{ value });
    }
  }
}

std::pair<u16, u16>
CommandLineRegistry::GetTerminalSize() const noexcept
{
  struct winsize terminalSize;

  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &terminalSize) == 0) {
    auto leftColumnWidth = static_cast<u16>(terminalSize.ws_col * 0.25);
    if (leftColumnWidth <= mLeftColumnDisplayWidth) {
      leftColumnWidth = mLeftColumnDisplayWidth + 1;
    } else {
      // Don't waste space, give the left column at most 8 characters of
      // trailing white space after it.
      leftColumnWidth = std::max<u16>(leftColumnWidth, mLeftColumnDisplayWidth + 4);
    }
    const auto rightColumnWidth = terminalSize.ws_col - leftColumnWidth;

    return std::pair<u16, u16>{ leftColumnWidth, rightColumnWidth };
  }
  perror("ioctl for winsize failed");
  return std::pair{ mLeftColumnDisplayWidth, 80 - mLeftColumnDisplayWidth };
}

void
CommandLineRegistry::PrintHelpAbout(const OptionMetadata &option, u16 leftColumn, u16 rightColumn) const noexcept
{
  UsagePrintFormatting arg{ option, leftColumn, rightColumn };
  std::println("{}", arg);
}

void
CommandLineRegistry::PrintHelp() const noexcept
{
  std::println("Usage:\n");
  std::println("  mdb [options]");
  std::println("Options:\n");

  auto size = GetTerminalSize();

  auto [leftColumn, rightColumn] = size;
  const auto options = GetOptions();

  for (const auto &option : options) {
    PrintHelpAbout(*option, leftColumn, rightColumn);
  }

  std::println("Environment variables:\n");
  const auto environmentVariables = GetEnvironmentVariableOptions();
  for (const auto &envVar : environmentVariables) {
    PrintHelpAbout(*envVar, leftColumn, rightColumn);
  }
}

} // namespace mdb::cfg