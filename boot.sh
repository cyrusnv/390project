#!/bin/bash

# This script compiles the target and tracer, then runs the tracer with the target

# Ensure we exit on any error
set -e

echo "Compiling target with exported symbols..."
# Compile the target with debug info and symbols exported
gcc -g -O0 -rdynamic target.c -o target

echo "Compiling tracer..."
# Compile the tracer
gcc -g tracer.c -o tracer

echo "Running tracer with target..."
# Run the tracer with the target path
./tracer ./target

echo "Boot process completed"