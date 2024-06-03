#include <cstdio>
// Test subject for Module and output events (even though every binary will always have a few module events output
// for them)

int
stdout_outputevent()
{
  std::printf("output event: hello world\n");
  // by this point we should have seen an output event.
  return 0; // STDIO_OUTPUT_EVENT_BP
}

int
main()
{
}