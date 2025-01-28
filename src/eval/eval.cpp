/** LICENSE TEMPLATE */
#include "eval.h"
#include <supervisor.h>

namespace mdb::eval {

EvaluationContext::EvaluationContext(TraceeController &tc, std::unique_ptr<mdb::ByteBuffer> &&buffer,
                                     int frame_id) noexcept
    : tc(tc), input(std::move(buffer)), frame_id(frame_id)
{
}

} // namespace mdb::eval