#!/usr/bin/env python2
import os
import sys
import readline
import datetime

readline.set_completer_delims(' \t\n=')
readline.parse_and_bind("tab: complete")

def print_logo():
    print("""

                           /@@@@@@@@@@@&&              
                        *@@@@@@@@@@@@@@@@@@@          
                      ,@@@@@@@@@@@@@@@@@@@@@&&        
                    .*(@&(((%@@@@@@@#(((@@@@@@**      
                    .@@@@@(   (@@@,   */@@@@@@@@         _____   _        ____     _____   _______ 
                    .@@@@@@@@@@@@@@@@@@@@@@@@@@@        / ____| | |      / __ \   / ____| |__   __|
                    .@@@@@@@@@@@@@@@@@@@@@@@@@@@       | |  __  | |__   | |  | | | (___      | | 
                    .@@@@@@@@@/   %@@@@@@@@@@@@@       | | |_ | | '_ \  | |  | |  \___ \     | |  
                    .@@@@@@@@@@@@@@@@@@@    @@@@       | |__| | | | | | | |__| |  ____) |    | |
                @@@& ,@@@@@@@@@@@@@@@. @@@@@@@@         \_____| |_| |_|  \____/  |_____/     |_|
                @&     ,%&@@@@@@@@@@@. @@  &&@@@@    
                            .,****%&@@%###@@@@@@&&,, 

                                  Ghidra Overflow Sink-to-Source Tracer
    """)
    print("\n    ==================================== Now with Tab Completion! ===========================================\n")

def main():

    print_logo()

    dir_path = os.path.dirname(os.path.realpath(__file__))
    ghidra_path = os.environ['GHIDRA_DIRECTORY']

    if not os.path.isfile(dir_path + '/ghost.py'):
        print("Please copy ghost.py to the same directory as this script")
        sys.exit(1)
    if not os.path.isfile(dir_path + '/ghidra_analysis_options_prescript.py'):
        print("Please copy ghidra_analysis_options_prescript.py to the same directory as this script")
        sys.exit(1)
    
    while True:
        program_to_analyze_directory = os.environ['INPUT_FOLDER']
        if program_to_analyze_directory[-1] != "/":
            program_to_analyze_directory+="/"
        if os.path.isdir(program_to_analyze_directory):
            break
        else:
            print("Invalid path. please enter a valid path.")
            sys.exit(1)

    for program in os.listdir(program_to_analyze_directory):
        try:
            output_directory = program_to_analyze_directory+program+'_output'
            os.makedirs(output_directory)
        except Exception as e:
            print("Output directory alread exists!")
            output_directory = datetime.datetime.now().strftime("%H:%M:%S") + program + "_output"
        
        os.environ['OUTPUT_DIRECTORY'] = output_directory
        os.environ['PROGRAM_NAME'] = program
        os.system("sh {} {} temporaryProjectA -import {} -preScript {} -postScript {} -deleteProject".format(ghidra_path, program_to_analyze_directory, program_to_analyze_directory+'/'+program, dir_path + "/ghidra_analysis_options_prescript.py", dir_path + "/ghost.py"))
        
if __name__ == "__main__":
    main()