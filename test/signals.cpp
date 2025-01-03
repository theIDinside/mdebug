#include <csignal>
#include <cstdio>
#include <cstring>


void RaiseSignal(int signal) {
  std::printf("Raise signal %d=%s\n", signal, strsignal(signal));
  raise(signal);
}

int
main(int argc, const char **argv)
{
  RaiseSignal(SIGINT);
  RaiseSignal(SIGTERM);
  return 0;
}