#!/bin/bash

fmt_version="10.0.0"

if [ ! -e "./dependencies/fmt" ]; then
  wget -P ./dependencies https://github.com/fmtlib/fmt/releases/download/$fmt_version/fmt-$fmt_version.zip
  unzip ./dependencies/fmt-$fmt_version.zip -d ./dependencies/
  mv ./dependencies/fmt-$fmt_version ./dependencies/fmt
  rm ./dependencies/fmt-$fmt_version.zip
  echo "libfmt dependency met"
else
  echo "libfmt dependency already met"
fi

