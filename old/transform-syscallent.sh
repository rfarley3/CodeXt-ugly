#!/bin/sh

cat syscallent.h | sed -re 's/^(.*\{[^,]*,[^,]*,)[^,]*,([^,]*)(,[^,]*)?(\},.*$)/\1\2\4/'  | grep -Ev '[:blank:]*#' > syscallent-simple.h
