# Singapore Polytechnic ITSP Final Year Project (Group 7) AY2022/23
# ARM Binary Reverse Engineering: Command Injection Vulnerability (FinjectRoute)

# Written by Koo Hao Ming 
# Tested using python 3.9.0
# The digraph generation script for FYP project

import graphviz,os
from pathlib import Path
from json import load

parentDir = Path(__file__).resolve().parent
OutputFilePath = Path(str(parentDir) + "/../Output/Graphs").resolve()

# **************************
# Functions for graph output
# **************************

# Function to combine both the function name and its address into one for easy reading
def combineKeyValue(items):
    for key, addr in items:
        keyAndAddr = (f"{key}_{addr}")
    return keyAndAddr

def replaceChar(functionStr):
    functionStr = functionStr.replace(':', '')
    functionStr = functionStr.replace('{', '\{')
    functionStr = functionStr.replace('}', '\}')
    functionStr = functionStr.replace('|', '\|')
    return functionStr

# For each function in the path, display the function name, address and useful strings for the digraphs
def FunctionDisplay(funcJSON):

    for function, usefulStrings in funcJSON.items():
        function = replaceChar(function)

        if (usefulStrings==[])==True:
            return function
        else:
            combinedStr = ''
            for currentStr in usefulStrings:
                currentStr = replaceChar(currentStr)
                combinedStr += f'{currentStr}\l'

            combinedName = f'{function}{combinedStr}'
            combinedOuput = ('{'+function+'\l|'+combinedStr+'}')

            return [combinedName, combinedOuput]


# create digraph for vulnerable paths
def createVulDigraph(sinkList, currentJSON_Name):
    global OutputFilePath
    # for loop to loop through all the sink functions and their paths
    for i in sinkList:
        # Create a new digraph for every vulnerable sink function
        f = graphviz.Digraph(f"Vul-{i}_{currentJSON_Name}")

        for currentNum in sinkList[i]:
            VulPath = pathData['vulnerable'][currentNum]
            sinkFunc = i
            f.node(sinkFunc, shape='oval')  
            
            # show all the paths to the sink function
            for paths in VulPath['Paths']:
                if len(paths) == 1:
                    currentFunct = FunctionDisplay(paths[0])
                    f.node(name=currentFunct[0], shape='record', label=currentFunct[1])
                    f.edge(currentFunct[0], sinkFunc)

                else:
                    for x in range(len(paths)):
                        currentFunct = FunctionDisplay(paths[x])
                        prevFunct = FunctionDisplay(paths[x-1])
                        f.node(name=currentFunct[0], shape='record', label=currentFunct[1])
                        f.node(name=prevFunct[0], shape='record', label=prevFunct[1])
                        
                        if(x==0):
                            f.edge(currentFunct[0], sinkFunc)

                        elif(x==(len(paths))-1):
                            f.edge(currentFunct[0], prevFunct[0])

                        else:
                            f.edge(currentFunct[0], prevFunct[0])
                    
        f.render(format='png',directory=OutputFilePath)
        
        # manage the files in the graph output folder to only have the png files
        if os.path.exists(f'{OutputFilePath}/Vul-{sinkFunc}_{currentJSON_Name}.png')==True:
            os.remove(f'{OutputFilePath}/Vul-{sinkFunc}_{currentJSON_Name}.png')
        os.rename(f'{OutputFilePath}/Vul-{sinkFunc}_{currentJSON_Name}.gv.png', f'{OutputFilePath}/Vul-{sinkFunc}_{currentJSON_Name}.png')
        os.remove(f'{OutputFilePath}/Vul-{sinkFunc}_{currentJSON_Name}.gv')

        print(f"Generating graph named Vul-{sinkFunc}_{currentJSON_Name}.png...")


# create digraph for non-vulnerable paths
def createNonVulDigraph(sinkList, currentJSON_Name):
    global OutputFilePath

    for i in sinkList:
        # Create a new digraph for every non-vulnerable sink function
        f = graphviz.Digraph(f"Non-Vul-{i}_{currentJSON_Name}")

        for currentNum in sinkList[i]:
            NonVulPath = pathData['non-vulnerable'][currentNum]
            sinkFunc = i
            f.node(sinkFunc, shape='oval')  
            
            # show all the paths to the sink function
            for paths in NonVulPath['Paths']:
                if len(paths) == 1:
                    currentFunct = FunctionDisplay(paths[0])
                    f.node(name=currentFunct[0], shape='record', label=currentFunct[1])
                    f.edge(currentFunct[0], sinkFunc)

                else:
                    for x in range(len(paths)):
                        currentFunct = FunctionDisplay(paths[x])
                        prevFunct = FunctionDisplay(paths[x-1])
                        f.node(name=currentFunct[0], shape='record', label=currentFunct[1])
                        f.node(name=prevFunct[0], shape='record', label=prevFunct[1])
                        
                        if(x==0):
                            f.edge(currentFunct[0], sinkFunc)

                        elif(x==(len(paths))-1):
                            f.edge(currentFunct[0], prevFunct[0])

                        else:
                            f.edge(currentFunct[0], prevFunct[0])
                    
        f.render(format='png',directory=OutputFilePath)
        
        # manage the files in the graph output folder to only have the png files
        if os.path.exists(f'{OutputFilePath}/Non-Vul-{sinkFunc}_{currentJSON_Name}.png')==True:
            os.remove(f'{OutputFilePath}/Non-Vul-{sinkFunc}_{currentJSON_Name}.png')
        os.rename(f'{OutputFilePath}/Non-Vul-{sinkFunc}_{currentJSON_Name}.gv.png', f'{OutputFilePath}/Non-Vul-{sinkFunc}_{currentJSON_Name}.png')
        os.remove(f'{OutputFilePath}/Non-Vul-{sinkFunc}_{currentJSON_Name}.gv')

        print(f"Generating graph named Non-Vul-{sinkFunc}_{currentJSON_Name}.png...")


# ********************
# Graph Output program
# ********************

input_path = str(parentDir) + "/tempJSON"
JSONfiles = os.listdir(input_path)

# Get all the json data from json files in the 'tempJSON' directory 
for currentfile in JSONfiles:
    if os.path.isfile(os.path.join(input_path, currentfile)):
        with open(os.path.join(input_path, currentfile)) as f:
            pathData = load(f)

    # Make dict for sink functions and their paths
    vulSinkFuncList = {}
    for i in range(len(pathData['vulnerable'])):
        sinkFunc = combineKeyValue(pathData['vulnerable'][i]['Sink Name'].items())
        # Ensure paths with the same sink function are grouped together
        if sinkFunc in vulSinkFuncList.keys():
            # If sink function is already a key, add the path's list number to the array
            vulSinkFuncList[sinkFunc].append(i)
        else:
            # If sink function is not a key, create a new key and value pair, with the value being array full of paths
            vulSinkFuncList[sinkFunc] = [i]

    # Same logic as vulnerable paths
    NonVulSinkFuncList = {}
    for i in range(len(pathData['non-vulnerable'])):
        sinkFunc = combineKeyValue(pathData['non-vulnerable'][i]['Sink Name'].items())
        if sinkFunc in NonVulSinkFuncList.keys():
            NonVulSinkFuncList[sinkFunc].append(i)
        else:
            NonVulSinkFuncList[sinkFunc] = [i]

    # Remove the json extension from the string
    JSONname,ext = os.path.splitext(currentfile)
    print("Generating Graphs......")
    # create a digraph for each sink functions
    createVulDigraph(vulSinkFuncList, str(JSONname))
    createNonVulDigraph(NonVulSinkFuncList, str(JSONname))

    print("Graph generation finished...")
