#!/bin/bash

fmt_version="10.0.0"
json_version="v3.11.2"
gtest_version="03597a01ee50ed33e9dfd640b249b4be3799d395"
distorm_version="3.5.2b"
# https://github.com/gdabah/distorm/archive/refs/tags/3.5.2b.tar.gz
# The relative path to repo root dir from where this script is executed,
# makes it safe to run from where ever.
relative_repo_root_dir="$(dirname "$0")"

# Begin by setting up distorm dependencies
if [ ! -e "$relative_repo_root_dir/dependencies/distorm" ]; then
  echo "Downloading distorm ..."
  wget -q -P $relative_repo_root_dir/dependencies https://github.com/gdabah/distorm/archive/refs/tags/3.5.2b.tar.gz
  echo "Done!"
  tar xf $relative_repo_root_dir/dependencies/3.5.2b.tar.gz -C $relative_repo_root_dir/dependencies/
  mv $relative_repo_root_dir/dependencies/distorm-3.5.2b $relative_repo_root_dir/dependencies/distorm
  rm $relative_repo_root_dir/dependencies/3.5.2b.tar.gz
  echo "Setting up CMake for distorm dependency..."
  cp $relative_repo_root_dir/generate/distorm_cmake.txt $relative_repo_root_dir/dependencies/distorm/CMakeLists.txt
  echo "distorm dependency configured"
else
  echo "distorm dependency already met"
fi

# Begin by setting up libfmt dependencies
if [ ! -e "$relative_repo_root_dir/dependencies/fmt" ]; then
  echo "Downloading libfmt ..."
  wget -q -P $relative_repo_root_dir/dependencies https://github.com/fmtlib/fmt/releases/download/$fmt_version/fmt-$fmt_version.zip
  echo "Done!"
  unzip -qq $relative_repo_root_dir/dependencies/fmt-$fmt_version.zip -d $relative_repo_root_dir/dependencies/
  mv $relative_repo_root_dir/dependencies/fmt-$fmt_version $relative_repo_root_dir/dependencies/fmt
  rm $relative_repo_root_dir/dependencies/fmt-$fmt_version.zip
  echo "libfmt dependency configured"
else
  echo "libfmt dependency already met"
fi

# Setup nlohmann_json dependencies
if [ ! -e "$relative_repo_root_dir/dependencies/nlohmann_json" ]; then
  echo "Downloading nlohmann_json ..."
  wget -q -P $relative_repo_root_dir/dependencies "https://github.com/nlohmann/json/releases/download/$json_version/json.tar.xz"
  echo "Done!"
  tar xf $relative_repo_root_dir/dependencies/json.tar.xz -C $relative_repo_root_dir/dependencies/
  mv $relative_repo_root_dir/dependencies/json $relative_repo_root_dir/dependencies/nlohmann_json
  rm $relative_repo_root_dir/dependencies/json.tar.xz
  echo "json dependency configured"
else
  echo "json already dependency met"
fi

# Setup google test for unit testing capabilities
if [ ! -e "$relative_repo_root_dir/dependencies/googletest" ]; then
  echo "Downloading googletest ..."
  wget -q -P $relative_repo_root_dir/dependencies "https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip" --output-document=$relative_repo_root_dir/dependencies/gtest.zip
  echo "Done!"
  unzip -qq $relative_repo_root_dir/dependencies/gtest.zip -d $relative_repo_root_dir/dependencies/
  mv "$relative_repo_root_dir/dependencies/googletest-$gtest_version" $relative_repo_root_dir/dependencies/googletest
  rm $relative_repo_root_dir/dependencies/gtest.zip
  echo "gtest dependency configured"
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