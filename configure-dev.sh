#!/bin/bash

fmt_version="10.0.0"

# The relative path to repo root dir from where this script is executed,
# makes it safe to run from where ever.
relative_repo_root_dir="$(dirname "$0")"

if [ ! -e "$relative_repo_root_dir/dependencies/fmt" ]; then
  wget -P $relative_repo_root_dir/dependencies https://github.com/fmtlib/fmt/releases/download/$fmt_version/fmt-$fmt_version.zip
  unzip $relative_repo_root_dir/dependencies/fmt-$fmt_version.zip -d $relative_repo_root_dir/dependencies/
  mv $relative_repo_root_dir/dependencies/fmt-$fmt_version $relative_repo_root_dir/dependencies/fmt
  rm $relative_repo_root_dir/dependencies/fmt-$fmt_version.zip
  echo "libfmt dependency met"
else
  echo "libfmt dependency already met"
fi

# Setup pre-commit formatting requirement hooks
cp $relative_repo_root_dir/setup/pre-commit $relative_repo_root_dir/.git/hooks/pre-commit

# Verify that clang-format exists on $PATH
which clang-format >/dev/null 2>&1
found=$?
if [ "$found" -eq 1 ]; then
  echo "You need to install clang-format or make sure that 'clang-format' can be found on $PATH - or you won't be able to contribute to MDB" 
else
  echo "clang-format found on \$PATH. You're good to go." 
fi