#include <iostream>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int
main(int argc, const char **argv)
{

  if (argc < 2) {
    std::cout << " you must provide the path to the application to be execed\n";
    exit(-1);
  }
  std::cout << "args passed to fork:\n";
  for (auto i = 1; i < argc; ++i) {
    std::cout << "arg: " << argv[i] << std::endl;
  }

  pid_t pid = fork();
  if (pid < 0) {
    // Fork failed
    std::cerr << "Fork failed" << std::endl;
    return 1;
  } else if (pid == 0) {
    // Child process
    std::cout << "Child process: Executing ls command" << std::endl;
    if (argc == 3) {
      execlp(argv[1], argv[1], "RunForever", NULL);
    } else {
      execlp(argv[1], argv[1], NULL);
    }

    // If execlp returns, it must have failed.
    std::cerr << "execlp failed" << std::endl;
    return 1;
  } else {
    // Parent process
    std::cout << "\n\nParent process: Waiting for child to complete\n" << std::endl;
    int status;
    waitpid(pid, &status, 0);
    std::cout << "\n\nParent process: Child completed with status " << status << std::endl;
  }

  return 0;
}
