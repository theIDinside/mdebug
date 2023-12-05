#include "source_file.h"

namespace sym {

CompilationUnit::CompilationUnit(sym::dw::UnitData *cu_data, dw::LineTable line_table)
    : unit_data(cu_data), low_pc(nullptr), high_pc(nullptr), line_table(line_table)
{
}

} // namespace sym