#include <filesystem>
#include <iostream>
#include <sys/wait.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <directory_path>" << std::endl;
    return 1;
  }

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
    programpath = programpath / "childprogram";

    std::cout << " exec=" << programpath << " with parameter: " << directoryPath
              << " . cwd=" << std::filesystem::current_path() << std::endl;

    execl(programpath.c_str(), programpath.c_str(), directoryPath.c_str(), nullptr); // #CHILD_EXEC_BP

    // If execl returns, it must have failed
    std::cerr << "Error: execl failed." << std::endl;
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
