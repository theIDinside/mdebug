#pragma once
#include "utils/byte_buffer.h"
#include "utils/immutable.h"

#include <cstdint>
#include <memory>
#include <typedefs.h>
#include <variant>

struct TraceeController;

namespace eval {

struct EvalValue
{
};

enum class ValueKind
{
  // Actual `Value`s retrieved from the tracee
  DebuggerValue,
  // "Supervisor" value kinds, values existing (only) in the evaluator context
  Variable,
  Number,
  String,
};

enum class Unary : u16
{
  Negate,
  Reference,
  DeReference,
  Constructor,
};

enum class BinaryOpKind : u8
{
  Add = '+',
  Subtract = '-',
  Divide = '/',
  Multiply = '*',
};

struct Token
{
};

struct Expr
{
};

struct BinaryExpr
{
};

class EvaluationContext
{
  TraceeController &tc;

public:
  EvaluationContext(TraceeController &tc, std::unique_ptr<utils::ByteBuffer> &&buffer, int frame_id) noexcept;
  Immutable<std::unique_ptr<utils::ByteBuffer>> input;
  Immutable<int> frame_id;
};

} // namespace eval