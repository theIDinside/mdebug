#include <cstring>
#include <filesystem>
#include <format>
#include <iostream>
#include <sys/wait.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
  if (argc < 3) {
    std::cerr << "Usage: <required params> |optional params|\n\t" << argv[0]
              << " <child program path> <directory_path> <sleep time in milliseconds>" << std::endl;
    return 1;
  }

  std::cout << "file: " << argv[0] << std::endl;
  std::cout << "child to execute: " <<  argv[1] << std::endl;
  std::cout << std::format("child 1st param: {}\n", argv[2]);
  std::cout << std::format("child 2nd param: {}\n", argv[3]);

  std::string directoryPath = argv[1];
  pid_t pid = fork();
  // THE DEBUGGER MASTER RACE IS HERE LOL
  if (pid == -1) {
    // Fork failed
    std::cerr << "Error: fork failed." << std::endl;
    return 1;
  } else if (pid == 0) {
    // Child process
    // Replace this with the path to the executable created from the previous program

    auto current = std::filesystem::current_path();
    std::filesystem::path programpath = directoryPath;
    programpath = current / "build" / "bin" / "childprogram";

    std::cout << " exec=" << programpath << " with parameter: " << directoryPath
              << " . cwd=" << std::filesystem::current_path() << std::endl;

    int res;
    if(argc == 3) {
      res = execl(argv[1], argv[1], argv[2], nullptr); // #CHILD_EXEC_BP
    } else {
      res = execl(argv[1], argv[1], argv[2], argv[3], nullptr);
    }

    // If execl returns, it must have failed
    std::cerr << "Error: execl failed exit code=" << res << ", error: " << strerror(errno) << std::endl;
    return 1;
  } else {
    // Parent process
    int status;
    waitpid(pid, &status, 0); // #PARENT_WAITPID
    if (WIFEXITED(status)) {
      std::cout << "Child process exited with status " << WEXITSTATUS(status) << std::endl;
    } else {
      std::cerr << "Child process did not exit successfully." << std::endl;
    }
  }

  return 0;
}
