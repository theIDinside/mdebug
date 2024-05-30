#!/bin/bash
echo "Setting up developer environment settings"

clearRecordings() {
  rrdir
  rm mdb-* -rf
  cd -
}

native() {
  ctest --output-on-failure --verbose -R Native.*$@
}

remote() {
  ctest --output-on-failure --verbose -R Remote.*$@
}

recnative() {
  REC=rr ctest --output-on-failure --verbose -R Native.*$@
}

recremote() {
  REC=rr ctest --output-on-failure --verbose -R Remote.*$@
}

drivertest () {
  ctest --output-on-failure $@
}

rectest () {
  REC=rr ctest --output-on-failure $@
}

buildmdb () {
  ninja mdb
}

tag_filenames() {
  if [ $# -lt 2 ]; then
		echo -e "Invalid argument count: $#\n\tUsage:  ${FUNCNAME[0]} <prefix> <file glob pattern>"
		return
  fi
	glob=$2
	prefix=$1
	for file in "${glob}";
	do
		echo "doing something with file: $file"
		if [ -e "$file" ]; then
			mv "${file}" "${prefix}${file}"
		fi
	done
}

