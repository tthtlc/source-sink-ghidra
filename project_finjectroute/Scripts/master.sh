#!/bin/bash

# Singapore Polytechnic ITSP Final Year Project (Group 7) AY2022/23
# ARM Binary Reverse Engineering: Command Injection Vulnerability (FinjectRoute)
# Master script, controls all other scripts in the program

# Written by: Chua Chok Yang

SCRIPTPATH=$(dirname "${BASH_SOURCE[0]}")
SCRIPTPATH=$(readlink -f "$SCRIPTPATH")

PREPROCESS=$SCRIPTPATH/preprocess.py
PDF=$SCRIPTPATH/generate_pdf.py
GRAPH=$SCRIPTPATH/generate_graphs.py
TAINTANALYSIS=Taint_Analysis_Script.java            # Use script name here and not script path
BINARIES=$SCRIPTPATH/Utility/binaries.txt
BANNER=$SCRIPTPATH/Utility/banner.txt

CONFIG=$SCRIPTPATH/Utility/config.json
HEADLESSANALYSER=`cat $CONFIG | tr -d '\n' | jq ".paths .analyzeHeadless" | tr -d '"'`
REPO=$SCRIPTPATH/../Repository/Temp
GHIDRAREPO=$SCRIPTPATH/../Repository/FinjectRoute_tmp
GRAPHFOLDER=$SCRIPTPATH/../Output/Graphs
TEMPJSON=$SCRIPTPATH/tempJSON

# read values from config file
VERBOSITY=`cat $CONFIG | tr -d '\n' | jq ".defaults .verbose" | tr -d '"'`
DEPTH=`cat $CONFIG | tr -d '\n' | jq ".defaults .depth" | tr -d '"'`


help(){
    echo "Usage: ./master.sh [OPTIONS]"
    echo "-h    Show this prompt."
    echo "-f    Firmware file to unpack and scan for binaries."
    echo "-F    Skip unpacking and scan a file directly."
    echo "-s    Skip unpacking and scan previously unpacked binary or specify a target directory to scan."
    echo "-v    Verbose mode, goes from levels 1-5, default is 1. Example: -v 3"
    echo "-b    Batch mode. Upon usage will skip unpacking of a binary and scan a text file for filepaths."
    echo "-d    Specify a depth level to use during the scanning of binaries, default is 15. Example: -d 10"
    echo "-D    Specify a target directory."
    echo "-u    Unpack a targeted firmware file but skip the scanning of binaries found within for command injection vulnerabilites"
}
while getopts hf:F:sv:b:D:d:u flag
do
    case "${flag}" in
        h) HELP=true;;
        f) FIRMWARE=${OPTARG};;
        F) FILE=${OPTARG};;
        s) SKIP=true;;
        v) VERBOSITY=${OPTARG};;
        b) BATCH=${OPTARG};;
        d) DEPTH=${OPTARG};;
        D) TARGETDIR=${OPTARG};;
        u) UNPACKONLY=true;;
    esac
done

rm $GHIDRAREPO/* 2> /dev/null
rm $GRAPHFOLDER/* 2> /dev/null
rm $TEMPJSON/* 2> /dev/null

if [ $HELP ] ; then
    help
    exit
elif [ $FIRMWARE ] ; then
    echo -e "$(cat $BANNER)"
    echo ""
    if [ $UNPACKONLY ] && [ $TARGETDIR ] ; then
        echo -e "\033[1;36mNow unpacking $FIRMWARE into $TARGETDIR\033[0;37m"
        python3 $PREPROCESS $FIRMWARE -f $TARGETDIR -o
    elif [ $UNPACKONLY ] ; then
        echo -e "\033[1;36mNow unpacking $FIRMWARE into $REPO \033[0;37m"
        python3 $PREPROCESS $FIRMWARE -f $REPO -o
    elif [ $TARGETDIR ] ; then
        echo -e "\033[1;36mNow unpacking $FIRMWARE into $TARGETDIR \033[0;37m"
        python3 $PREPROCESS $FIRMWARE -f $TARGETDIR -o
        cat $BINARIES | while read line ; do
            echo -e "\033[1;36mNow scanning $line for command injection vulnerabilities\033[0;37m"
            $HEADLESSANALYSER $GHIDRAREPO PcodeExtractor -import $line -postScript $TAINTANALYSIS @v $VERBOSITY @d $DEPTH @s $SCRIPTPATH -scriptPath $SCRIPTPATH -deleteProject
        done
        echo ""
        python3 $GRAPH
        echo ""
        python3 $PDF
    else
        echo -e "\033[1;36mNow unpacking $FIRMWARE into $REPO \033[0;37m"
        python3 $PREPROCESS $FIRMWARE -f $REPO -o
        cat $BINARIES | while read line ; do
            echo -e "\033[1;36mNow scanning $line for command injection vulnerabilities\033[0;37m"
            $HEADLESSANALYSER $GHIDRAREPO PcodeExtractor -import $line -postScript $TAINTANALYSIS @v $VERBOSITY @d $DEPTH @s $SCRIPTPATH -scriptPath $SCRIPTPATH -deleteProject
        done
        echo ""
        python3 $GRAPH
        echo ""
        python3 $PDF
    fi
elif [ $SKIP ] ; then
    echo -e "$(cat $BANNER)"
    echo ""
    if [ $TARGETDIR ] ; then
        python3 $PREPROCESS $TARGETDIR -s
        cat $BINARIES | while read line ; do
            echo -e "\033[1;36mNow scanning $line for command injection vulnerabilities\033[0;37m\n"
            $HEADLESSANALYSER $GHIDRAREPO PcodeExtractor -import $line -postScript $TAINTANALYSIS @v $VERBOSITY @d $DEPTH @s $SCRIPTPATH -scriptPath $SCRIPTPATH -deleteProject
        done
        echo ""
        python3 $GRAPH
        echo ""
        python3 $PDF
    else
        python3 $PREPROCESS $REPO -s
        cat $BINARIES | while read line ; do
            echo -e "\033[1;36mNow scanning $line for command injection vulnerabilities\033[0;37m\n"
            $HEADLESSANALYSER $GHIDRAREPO PcodeExtractor -import $line -postScript $TAINTANALYSIS @v $VERBOSITY @d $DEPTH @s $SCRIPTPATH -scriptPath $SCRIPTPATH -deleteProject
        done
        echo ""
        python3 $GRAPH
        echo ""
        python3 $PDF
    fi
elif [ $BATCH ] ; then
    echo -e "$(cat $BANNER)"
    echo ""
    cat $BATCH | while read line ; do
        echo -e "\033[1;36mNow scanning $line for command injection vulnerabilities\033[0;37m\n"
        $HEADLESSANALYSER $GHIDRAREPO PcodeExtractor -import $line -postScript $TAINTANALYSIS @v $VERBOSITY @d $DEPTH @s $SCRIPTPATH -scriptPath $SCRIPTPATH -deleteProject
    done
    echo ""
    python3 $GRAPH
    echo ""
    python3 $PDF
elif [ $FILE ] ; then
    echo -e "$(cat $BANNER)"
    echo ""
    echo -e "\033[1;36mNow scanning $FILE for command injection vulnerabilities\033[0;37m\n"
    $HEADLESSANALYSER $GHIDRAREPO PcodeExtractor -import $FILE -postScript $TAINTANALYSIS @v $VERBOSITY @d $DEPTH @s $SCRIPTPATH -scriptPath $SCRIPTPATH -deleteProject
    echo ""
    python3 $GRAPH
    echo ""
    python3 $PDF
else
    echo "Usage: ./master.sh [OPTIONS]."
    echo "Use -h to show the help prompt."
fi
