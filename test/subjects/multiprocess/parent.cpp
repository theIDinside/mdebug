#include <chrono>
#include <cstring>
#include <filesystem>
#include <format>
#include <print>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;

using Path = fs::path;

static int
Exec(const std::vector<std::string> &execArgs)
{
  if (execArgs.empty()) {
    errno = EINVAL;
    return -1;
  }

  // Build argv for execve
  std::vector<char *> argv;
  argv.reserve(execArgs.size() + 1);

  for (const auto &arg : execArgs) {
    // const_cast is safe because execve() does not modify the strings themselves
    argv.push_back(const_cast<char *>(arg.c_str()));
  }
  argv.push_back(nullptr); // must be nullptr-terminated

  // Call execve. We pass `environ` to inherit the current environment.
  extern char **environ;
  std::println("execve({}, {}, nullptr)", argv[0], std::span{ argv }.subspan(0, argv.size() - 1));
  return execve(argv[0], argv.data(), environ);
}

int
main(int argc, char *argv[])
{
  if (argc < 3) {
    std::println(stderr,
      "Usage: <required params> |optional params|\n\t {} <child program path> <directory_path> <sleep time in "
      "milliseconds>",
      argv[0]);
    return 1;
  }

  std::println("file {}", argv[0]);
  std::println("child to execute: {}", argv[1]);
  std::println("child 1st param: {}", argv[2]);
  std::println("child 2nd param: {}", argv[3]);

  std::vector<std::string> execArguments{};
  for (auto arg : std::span{ argv + 1, argv + argc }) {
    execArguments.emplace_back(arg);
  }

  pid_t pid = fork();

  if (pid == -1) {
    // Fork failed
    std::println(stderr, "[Error] fork failed: {}", strerror(errno));
    return 1;
  } else if (pid == 0) {
    // Child process
    // Replace this with the path to the executable created from the previous program

    int res = Exec(execArguments);
    if (argc == 3) {
      std::println("execl({}, {}, {}, nullptr)", argv[1], argv[1], argv[2]);
      res = execl(argv[1], argv[1], argv[2], nullptr); // #CHILD_EXEC_BP
    } else {
      std::println("execl({}, {}, {}, {}, nullptr)", argv[1], argv[1], argv[2], argv[3]);
      res = execl(argv[1], argv[1], argv[2], argv[3], nullptr);
    }

    // If execl returns, it must have failed
    std::println(stderr, "Error: execl failed exit code={}, error={}", res, strerror(errno));
    return 1;
  } else {
    // Parent process
    int status;
    // to introduce some multi-threadedness.
    std::atomic<bool> exitThread = false;
    std::thread bg_thr{ [&]() {
      for (; !exitThread;) {
        std::this_thread::sleep_for(std::chrono::milliseconds{ 1000 });
        std::println("Yaaaaaaawn I, thread {}, just woke up", std::this_thread::get_id());
      }
    } };
    waitpid(pid, &status, 0); // #PARENT_WAITPID
    if (WIFEXITED(status)) {
      std::println("Child process exited with status={}", WEXITSTATUS(status));
    } else {
      std::println(stderr, "Child process did not exit successfully.");
    }
    exitThread = true;
    bg_thr.join();
  }

  return 0;
}
