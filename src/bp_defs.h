/** LICENSE TEMPLATE */
#pragma once
#include <cstdint>
#include <format>

namespace mdb {

enum class BreakpointBehavior : std::uint8_t
{
  StopAllThreadsWhenHit,
  StopOnlyThreadThatHit
};

enum class BreakpointRequestKind : std::uint8_t
{
  source,
  function,
  instruction,
  data,
  exception,
};

enum class LocationUserKind : std::uint8_t
{
  Address,
  Source,
  Function,
  FinishFunction,
  LogPoint,
  ResumeTo,
  SharedObjectLoaded,
  Exception,
  LongJump,
  Maintenance
};
} // namespace mdb

template <> struct std::formatter<mdb::LocationUserKind>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const mdb::LocationUserKind &kind, FormatContext &ctx) const
  {
    switch (kind) {
    case mdb::LocationUserKind::Address:
      return std::format_to(ctx.out(), "Address");
    case mdb::LocationUserKind::Source:
      return std::format_to(ctx.out(), "Source");
    case mdb::LocationUserKind::Function:
      return std::format_to(ctx.out(), "Function");
    case mdb::LocationUserKind::FinishFunction:
      return std::format_to(ctx.out(), "FinishFunction");
    case mdb::LocationUserKind::LogPoint:
      return std::format_to(ctx.out(), "LogPoint");
    case mdb::LocationUserKind::ResumeTo:
      return std::format_to(ctx.out(), "ResumeTo");
    case mdb::LocationUserKind::SharedObjectLoaded:
      return std::format_to(ctx.out(), "SharedObjectLoaded");
    case mdb::LocationUserKind::Exception:
      return std::format_to(ctx.out(), "Exception");
    case mdb::LocationUserKind::LongJump:
      return std::format_to(ctx.out(), "LongJump");
    case mdb::LocationUserKind::Maintenance:
      return std::format_to(ctx.out(), "Maintenance");
      break;
    }
    return std::format_to(ctx.out(), "Unknown");
  }
};