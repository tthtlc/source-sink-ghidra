# FinjectRoute: Command Injection Vulnerable Path Analyser

The project aims to develop a tool to automate and simplify the process of identifying vulnerable execution paths leading to command injection in binaries.

Through the use of this tool, breakdown and analysis of such sink-source paths should be made easier and faster for reverse engineers, with an emphasis for greater visual representations as well as understandable output and logging for reference.

# Original Authors

Chua Chok Yang,
Koo Hao Ming,
Koh Yuan Xun Ethan,
Lim Su Shuan Sammi, 
Melodi Joy Halim. 

# Docker Setup

The docker version of the tool is recommended for users.

For first time use, simply execute the docker_setup.sh script provided in the main tool folder.
```
$ cd FinjectRoute-docker
$ ./docker_setup.sh
```

Alternatively, if Docker is already installed on the system, use:
```
$ ./docker_setup.sh -s
```
# Using FinjectRoute

Once it is set up, to begin using the tool everytime, execute finjectroute_docker_run.sh.
```
$ ./finjectroute_docker_run.sh
```

You will enter the container at the folder /home/FinjectRoute-main/Scripts.

From then on you may begin the use of FinjectRoute by executing master.sh with the relevant options (enter -h for options):
```
$  ./master.sh -h
```

- To input a binary from the host system to the container, copy the binary into the mounted `Input` folder from outside the container.
- All main output from the tool (including generated PDFs and graphs) can be found in the mounted `Output` folder.
- As for logs, they may be found in the mounted `Logs` folder

# Examples

Some common uses will involve scanning 1 binary:
```
$ ./master.sh -F ../Input/test
```

Or scanning a directory of binaries:
```
$ ./master.sh -s -D ../Input
```
