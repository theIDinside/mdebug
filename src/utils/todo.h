#pragma once

// mdb
#include <common/macros.h>
#include <utils/logger.h>

// std
#include <iostream>
#include <print>
#include <source_location>

#define IGNORE_WARN(...) (void)sizeof...(__VA_OPT__(, ) __VA_ARGS__);

template <typename... Args>
consteval void
IgnoreArgs(const Args &...args)
{
  ((void)args, ...);
}

#define IGNORE_ARGS(...) IgnoreArgs(__VA_ARGS__)

#define TODO(abort_msg)                                                                                           \
  {                                                                                                               \
    auto loc = std::source_location::current();                                                                   \
    const auto todo_msg = std::format("[TODO]: {}\nin {}:{}", abort_msg, loc.file_name(), loc.line());            \
    std::println("{}", todo_msg);                                                                                 \
    mdb::logging::Logger::GetLogger()->GetLogChannel(Channel::core)->Log(todo_msg);                               \
    mdb::logging::Logger::GetLogger()->OnAbort();                                                                 \
    std::terminate(); /** Silence moronic GCC warnings. */                                                        \
    MIDAS_UNREACHABLE                                                                                             \
  }

#define TODO_IGNORE_WARN(message, ...)                                                                            \
  IgnoreArgs(__VA_ARGS__);                                                                                        \
  TODO(message);

#define TODO_FMT(fmt_str, ...)                                                                                    \
  {                                                                                                               \
    auto loc = std::source_location::current();                                                                   \
    const auto todo_msg_hdr =                                                                                     \
      std::format("[TODO {}] in {}:{}", loc.function_name(), loc.file_name(), loc.line());                        \
    const auto todo_msg = std::format(fmt_str __VA_OPT__(, ) __VA_ARGS__);                                        \
    std::println("{}", todo_msg_hdr);                                                                             \
    std::println("{}", todo_msg);                                                                                 \
    mdb::logging::GetLogChannel(Channel::core)->Log(todo_msg_hdr);                                                \
    mdb::logging::GetLogChannel(Channel::core)->Log(todo_msg);                                                    \
    mdb::logging::Logger::GetLogger()->OnAbort();                                                                 \
    std::terminate(); /** Silence moronic GCC warnings. */                                                        \
    MIDAS_UNREACHABLE                                                                                             \
  }