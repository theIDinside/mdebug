#include <csignal>
#include <cstdio>
#include <cstring>



void RaiseSignal(int signal) {
  std::printf("Raise signal %d=%s\n", signal, strsignal(signal));
  raise(signal);
}

void HandleSigint(int signal) {
    if(signal != SIGINT) {
      std::printf("Sigint signal handler called with another signal?!\n");
    } else {
      std::printf("SIGINT handled!\n");
    }
}

int
main(int argc, const char **argv)
{
  std::signal(SIGINT, HandleSigint);
  RaiseSignal(SIGINT);
  RaiseSignal(SIGTERM);
  std::printf("Since we signal sigterm, we should not see this if we have SIGTERM as allow-pass.\n");
  return 0;
}