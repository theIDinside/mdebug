import sys
import os

def find_syscall_definitions_file():
    try:
      file = open("/usr/include/asm/unistd_64.h", "r")
      return file
    except:
      exit(-1)


syscalls_file = find_syscall_definitions_file()
syscalls = []
try:
  for line in syscalls_file.readlines():
    if "__NR" in line:
      (name, syscall_number) = line.removeprefix("#define __NR_").split(" ")
      number = int(syscall_number)
      capitalized = "".join([x.capitalize() for x in name.split("_")])
      syscalls.append(f"SYSCALL({number}, {capitalized})\n")
except Exception as ex:
  print(f"Generate syscalls.def failed {ex}", file=sys.stderr)
  exit(-1)

path = os.path.dirname(__file__)
(src_root, _) = os.path.split(path)
output_file_path = os.path.join(src_root, "src", "defs", "syscalls.def")
output_file = open(output_file_path, "w")
output_file.write("/* GENERATED FILE - DO NOT ALTER */\n")
output_file.writelines(syscalls)

output_file.flush()
output_file.close()

exit(0)