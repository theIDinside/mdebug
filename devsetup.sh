#!/bin/bash
echo "Setting up developer environment settings"

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