/** LICENSE TEMPLATE */
#include "eval.h"
#include <supervisor.h>

namespace eval {

EvaluationContext::EvaluationContext(TraceeController &tc, std::unique_ptr<utils::ByteBuffer> &&buffer,
                                     int frame_id) noexcept
    : tc(tc), input(std::move(buffer)), frame_id(frame_id)
{
}

} // namespace eval