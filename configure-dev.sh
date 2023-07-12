#!/bin/bash

fmt_version="10.0.0"
json_version="v3.11.2"
gtest_version="03597a01ee50ed33e9dfd640b249b4be3799d395"
# The relative path to repo root dir from where this script is executed,
# makes it safe to run from where ever.
relative_repo_root_dir="$(dirname "$0")"

# Begin by setting up libfmt dependencies
if [ ! -e "$relative_repo_root_dir/dependencies/fmt" ]; then
  wget -P $relative_repo_root_dir/dependencies https://github.com/fmtlib/fmt/releases/download/$fmt_version/fmt-$fmt_version.zip
  unzip $relative_repo_root_dir/dependencies/fmt-$fmt_version.zip -d $relative_repo_root_dir/dependencies/
  mv $relative_repo_root_dir/dependencies/fmt-$fmt_version $relative_repo_root_dir/dependencies/fmt
  rm $relative_repo_root_dir/dependencies/fmt-$fmt_version.zip
  echo "libfmt dependency met"
else
  echo "libfmt dependency already met"
fi

# Setup nlohmann_json dependencies
if [ ! -e "$relative_repo_root_dir/dependencies/nlohmann_json" ]; then
  wget -P $relative_repo_root_dir/dependencies "https://github.com/nlohmann/json/releases/download/$json_version/json.tar.xz"
  tar xvf $relative_repo_root_dir/dependencies/json.tar.xz
  mv $relative_repo_root_dir/dependencies/json $relative_repo_root_dir/dependencies/nlohmann_json
  rm $relative_repo_root_dir/dependencies/json.tar.xz
  echo "json dependency met"
else
  echo "json already dependency met"
fi

# Setup google test for unit testing capabilities
if [ ! -e "$relative_repo_root_dir/dependencies/googletest" ]; then
  wget -P $relative_repo_root_dir/dependencies "https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip" --output-document=$relative_repo_root_dir/dependencies/gtest.zip
  unzip $relative_repo_root_dir/dependencies/gtest.zip
  mv "$relative_repo_root_dir/dependencies/googletest-$gtest_version" $relative_repo_root_dir/dependencies/googletest
  rm $relative_repo_root_dir/dependencies/gtest.zip
  echo "gtest dependency met"
else
  echo "gtest dependency met"
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