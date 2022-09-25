# Singapore Polytechnic ITSP Final Year Project (Group 7) AY2022/23
# ARM Binary Reverse Engineering: Command Injection Vulnerability (FinjectRoute)
# Code for the generation of a PDF report

# Written by: Koh Yuan Xun, Ethan
# Tested with: Python 3.8.10

from os import path, makedirs
from datetime import datetime

def generate_folder():
    dir_path = path.dirname(path.abspath(__file__))
    date_now = datetime.now()
    folder_name = ('../Output/PDFs/PDF_'+ date_now.strftime('%d%b_%H%M'))

    folder_path = path.join(dir_path, folder_name)
    #print(folder_path)

    if not path.exists(folder_path):
        makedirs(folder_path)

    return folder_name