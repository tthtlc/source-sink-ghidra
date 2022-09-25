#!/bin/bash

# Singapore Polytechnic ITSP Final Year Project (Group 7) AY2022/23
# ARM Binary Reverse Engineering: Command Injection Vulnerability (FinjectRoute)
# set up docker and docker images as well as filesystem necessary

# Written by: Chua Chok Yang

SCRIPTPATH=$(dirname "${BASH_SOURCE[0]}")
SCRIPTPATH=$(readlink -f "$SCRIPTPATH")

# Build docker image
echo "Now building finjectroute docker image..."
docker build -t finjectroute $SCRIPTPATH/

# Create file structure
echo "Now creating file structure..."
mkdir -p $SCRIPTPATH/Output/PDFs
mkdir -p $SCRIPTPATH/Output/Graphs
mkdir -p $SCRIPTPATH/Input
mkdir -p $SCRIPTPATH/Logs
chmod -R 777 $SCRIPTPATH
