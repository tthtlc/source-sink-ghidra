#!/bin/python3

# Singapore Polytechnic ITSP Final Year Project (Group 7) AY2022/23
# ARM Binary Reverse Engineering: Command Injection Vulnerability (FinjectRoute)
# Code for the preprocessing of firmware files and ELF binary files

# Written by: Chua Chok Yang
# Tested with: Python 3.8.10

from binwalk import scan
from pathlib import Path
from shutil import rmtree, move
from os import listdir, mkdir, rmdir, walk
from os.path import islink, isdir
from argparse import ArgumentParser
from json import load, dump

parentDir = Path(__file__).resolve().parent


# Argument parsing and global variables
elfSignature = hex(0x7F454C46)
parser = ArgumentParser("Unpacks a firmware file and scans it for ELF binaries.")
parser.add_argument("file", help="Firmware file to unpack or if -s/--skip is used, folder to scan for ELF binaries.")
parser.add_argument("-o", "--overwrite", help="Overwrite an already existing folder.", action="store_true", default=False)
parser.add_argument("-f", "--folder", help="Target folder to extract to.", default=f"./")
parser.add_argument("-s", "--skip", help="Skip extraction and scan an existing folder recursively for ELF binaries.", action="store_true", default=False)
args = parser.parse_args()
if args.skip:
    targetFolder = Path(args.file).resolve()
    print(f"Skipping extraction and scanning {targetFolder}.")
else: 
    targetFile = Path(args.file)
    targetFolder = Path(args.folder).resolve()
    binwalkTarget = targetFolder
    targetFolder = str(targetFolder) + f"/_{targetFile.name}.extracted"
    
# Get root of extracted filesystem
def locateRoot():
    global parentDir
    for currentpath, folders, files in walk(targetFolder):
        if 'bin' and "lib" and "usr" in folders:
            print(f"Root dir of firmware determined to be {currentpath}.")
            with open(str(parentDir) + "/Utility/config.json", "r") as f:
                data = load(f)
            with open(str(parentDir) + "/Utility/config.json", "w") as f:
                data["paths"]["rootDir"] = currentpath
                dump(data, f, indent=4)
                break

# Binwalk folder bug compensation
def folderErrorCheck(scanResult):
    global targetFolder
    unpacked = []
    carved = []
    for module in scanResult:
        for result in module.results:
            if result.file.path in module.extractor.output:
                if result.offset in module.extractor.output[result.file.path].carved:
                    carved.append(module.extractor.output[result.file.path].carved[result.offset])
                if result.offset in module.extractor.output[result.file.path].extracted:
                    unpacked.append(module.extractor.output[result.file.path].extracted[result.offset].files[0])
    combined = carved + unpacked
    if len(combined) != 0:
        if targetFolder not in combined[0]:
            mkdir(targetFolder)
            for i in carved:
                move(i, str(targetFolder))
            for i in unpacked:
                move(i, str(targetFolder))
            oldFolder = combined[0]
            oldFolder = oldFolder.split("/")
            oldFolder.pop()
            oldFolder = "/".join(oldFolder)
            rmdir(oldFolder)
            return
    else:
        print("Nothing was extracted.")
        return



# Function to extract firmware
def extractFirmware():
    global args
    global targetFile
    global targetFolder
    global binwalkTarget
    print(f"Extracting to {targetFolder}")
    if args.overwrite:
        rmtree(targetFolder, ignore_errors=True)
        extracted = scan(str(targetFile), signature=True, extract=True, quiet=True, directory=binwalkTarget, **{"run-as" : "root"})
        folderErrorCheck(extracted)
    elif not isdir(targetFolder) or not listdir(targetFolder):
        extracted = scan(str(targetFile), signature=True, extract=True, quiet=True, directory=binwalkTarget, **{"run-as" : "root"})
        folderErrorCheck(extracted)
    else:
        print("Operation Aborted. Directory not empty, use -o to overwrite.")
        return "ABORT"

# Scans for files within a given directory
def getFiles():
    global elfSignature
    allBinaries = ""
    print(f"Now scanning {targetFolder}")
    for file in Path(targetFolder).rglob("*"):
        byte = b""
        try:
            if not islink(str(file)):
                with open(file, "rb") as f:
                    byte = f.read(4)
                    if byte.hex() in elfSignature:    # Currently processing all files with elf headers, including library files
                        allBinaries += str(file) + "\n"
                        print(f"Binary found: {file}")
        except (IsADirectoryError):
            continue
    with open(str(parentDir) + "/Utility/binaries.txt", "w") as f:
        f.write(allBinaries)


def main():
    proceed = ""
    if not args.skip:
        proceed = extractFirmware()
        locateRoot()
    if proceed != "ABORT":
        getFiles()


main()
