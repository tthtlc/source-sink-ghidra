#!/bin/bash

# Singapore Polytechnic ITSP Final Year Project (Group 7) AY2022/23
# ARM Binary Reverse Engineering: Command Injection Vulnerability (FinjectRoute)
# Start docker container and mount appropriate directores

# Written by: Chua Chok Yang

docker run -it \
--rm \
--mount type=bind,source="$(pwd)"/Output,target=/home/FinjectRoute-main/Output \
--mount type=bind,source="$(pwd)"/Logs,target=/home/FinjectRoute-main/Logs \
--mount type=bind,source="$(pwd)"/Input,target=/home/FinjectRoute-main/Input \
finjectroute bash
