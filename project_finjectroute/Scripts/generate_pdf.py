# Singapore Polytechnic ITSP Final Year Project (Group 7) AY2022/23
# ARM Binary Reverse Engineering: Command Injection Vulnerability (FinjectRoute)
# Code for the generation of a PDF report

# Written by: Koh Yuan Xun, Ethan
# Tested with: Python 3.8.10

from reportlab.lib.units import inch, cm
from reportlab.lib import colors, utils
from reportlab.rl_config import defaultPageSize
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Image, BaseDocTemplate
from reportlab.lib.styles import (ParagraphStyle, getSampleStyleSheet)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.platypus.tables import Table, TableStyle
from reportlab.graphics.shapes import Drawing, Line
#from reportlab.pdfgen.canvas import Canvas
#from reportlab.pdfbase.pdfmetrics import stringWidth

global path
from os import path, listdir, rmdir, remove
from json import load
from datetime import datetime
from traceback import print_exc
import generate_folder

# NOTE: PRE-REQUSITIE: do a 'pip install reportlab' and make sure there is no file called 'reportlab.py' else it will throw errors.

PAGE_WIDTH=defaultPageSize[0]; PAGE_HEIGHT=defaultPageSize[1]
styles = getSampleStyleSheet()

## Setting filepaths

filepath = path.dirname(path.abspath(__file__))   # change if necessary

json_folder = path.join(filepath, './tempJSON')
graph_folder = path.join(filepath, '../Output/Graphs')
json_files = listdir(json_folder)
graph_files = listdir(graph_folder)
img_logo = path.join(filepath, './Utility/finjectBLACK.png')


# ======================== Classes ==========================

## Generations of Table of Contents

class MyDocTemplate(SimpleDocTemplate):

    def afterFlowable(self, flowable):
        "Registers TOC entries."
        if flowable.__class__.__name__ == 'Paragraph':
            text = flowable.getPlainText()
            style = flowable.style.name
            if style == 'Heading1':
                key = 'h1-%s' % self.seq.nextf('heading1')
                self.canv.bookmarkPage(key)
                self.notify('TOCEntry', (0, text, self.page, key))
            if style == 'Heading2':
                key = 'h2-%s' % self.seq.nextf('heading2')
                self.canv.bookmarkPage(key)
                self.notify('TOCEntry', (1, text, self.page, key))
            if style == 'Heading3':
                key = 'h3-%s' % self.seq.nextf('heading3')
                self.canv.bookmarkPage(key)
                self.notify('TOCEntry', (2, text, self.page, key))

# ======================== End of Classes ==========================

# ======================== Functions ========================

## Resize graph image

def get_image(path, width=1*cm):
    img = utils.ImageReader(path)
    iw, ih = img.getSize()
    aspect = ih / float(iw)

    if ((width * aspect) > 480):
        image_height = 480
        image_width = 480 / aspect
    else:
        image_height = width * aspect + (1*cm)
        image_width = width

    return Image(path, width=image_width, height=image_height)


## Replace string with html code

def str_replace(str):

    str = str.replace('\n','<br />')
    str = str.replace('  ','&nbsp;&nbsp;&nbsp;&nbsp;')

    return str


## Creating taint graphs section

def taint_graphs(Story, binary_name, data, state):

    ## Generate header

    if state == 'vul':
        heading = f'<font face="Times"><b>Taint graphs on vulnerabilities</b></font>'
    elif state == 'non-vul':
        heading = f'<font face="Times"><b>Taint graphs on non-vulnerabilities</b></font>'
    heading = str_replace(heading)

    p_heading = Paragraph(heading, styles["Heading1"])
    Story.append(p_heading)
    Story.append(line)


    ## Summary on the vulnerabilities and non-vulnerabilities

    taint_num = 1     # taint summary count

    for taint_data in data:

        ## Obtaining sink information

        sink_dict = taint_data['Sink Name']
        sink_name = list(sink_dict.keys())[0]
        sink_address = sink_dict[sink_name]          
        
        source_comment = taint_data['Source Comment']
        if source_comment == None or source_comment == '':
            source_comment = 'no comments'
    
        ## PDF content (make sure <para> tag only exist at the start and end of each string)

        if state == 'vul':
            str_header = f'<para size="11" color="red"><u>Vulnerable Graph #{taint_num}</u> [ {sink_name} @ {sink_address} ]</para>'
        elif state == 'non-vul':
            str_header = f'<para size="11" color="green"><u>Non-Vulnerable Graph #{taint_num}</u> [ {sink_name} @ {sink_address} ]</para>'
        p_str_heading = Paragraph(str_header, styles["Heading2"])
        Story.append(p_str_heading)

        str = f'<para borderwidth="1" borderpadding="4" bordercolor="black"><b>Sink Name:</b> {sink_name}\n'
        str += f'<b>Sink Address:</b> <font color="red">{sink_address}</font>\n'
        if state == 'vul':
            str += f'<b>Comments:</b> <i>{source_comment}</i></para>'  
        elif state == 'non-vul':
            str += f'\n</para>'
        str = str_replace(str)

        
        ## Obtaining graph image for vulnerabilities/non-vulnerabilities
        
        if state == 'vul':
            img_path = path.join(graph_folder, f'Vul-{sink_name}_{sink_address}_{binary_name}.png')
        elif state == 'non-vul':
            img_path = path.join(graph_folder, f'Non-Vul-{sink_name}_{sink_address}_{binary_name}.png')          
        img_data = path.join(filepath, img_path)
        
        ## Appending details and image of graph to the document
        
        p1 = Paragraph(str, styles["BodyText"])
        Story.append(p1)
        if path.exists(img_data)==True:
            Story.append(Spacer(width=0.5*cm,height=0.5*cm))
            Story.append(get_image(img_data, width=14.5*cm))
            # max width (units): 439.27559055118115, max height (units): 685.8897637795277
        else:
            p2 = Paragraph(f'<para spaceBefore="16">Image does not exist</para>', styles["Italic"])
            Story.append(p2)           
        Story.append(PageBreak())

        taint_num += 1

    return


## Details on vulnerabilities found 

def taint_details(Story, data, state):
    
    ## Generate header
    
    if state == 'vul':
        heading = f'<font face="Times"><b>Taint path details on vulnerabilities</b></font>'
    elif state == 'non-vul':
        heading = f'<font face="Times"><b>Taint path details on non-vulnerabilities</b></font>'
    heading = str_replace(heading)

    p_heading = Paragraph(heading, styles["Heading1"])
    Story.append(p_heading)
    Story.append(line)

    sink_num = 1        # sink count

    for taint_data in data:
        
        sink_dict = taint_data['Sink Name']
        sink_name = list(sink_dict.keys())[0]
        sink_address = sink_dict[sink_name]


        ## PDF content (make sure <para> tag only exist at the start and end of each string)
        if state == 'vul':
            str_header = f'<para size="11" color="red"><b><u>Vulnerable Sink #{sink_num}</u> [ @ {sink_address} ]</b></para>'
        elif state == 'non-vul':
            str_header = f'<para size="11" color="red"><b><u>Non-Vulnerable Sink #{sink_num}</u> [ @ {sink_address} ]</b></para>'
        p_str_heading = Paragraph(str_header, styles["Heading2"])
        Story.append(p_str_heading)

        str = f'<para borderwidth="1" borderpadding="4" bordercolor="black"><b>Sink Name:</b> {sink_name}\n'
        str += f'<b>Sink Address:</b> <font color="red">{sink_address}</font>\n\n'
        str += '</para>'
        str = str_replace(str)
        
        p = Paragraph(str, styles["BodyText"])

        Story.append(p)
        Story.append(Spacer(width=0.5*cm,height=0.5*cm))


        paths_list = taint_data['Paths']

        ## For loop to generate the path from source to sink (depending on depthLevel)

        path_num = 1      ## path count

        for vul_path in paths_list:

            count = 1       ## arrow count
            
            Story.append(Paragraph(f'Path #{path_num} [ {sink_name} ]', styles['Heading3']))
            Story.append(Spacer(width=0.5*cm,height=0.5*cm))
            
            if path_num != len(paths_list):
                path_num += 1

            for path_info in vul_path:

                function_name_and_address = list(path_info.keys())[0]
                function_name = function_name_and_address.split('@')[0].strip() 

                p_function_name = f'<para color="white"><a href="#{function_name}"><b><u>{function_name_and_address}</u></b></a></para>'     # Creating internal links within the PDF
                p4 = Paragraph(p_function_name, styles['BodyText'])

                function_instructions = path_info[function_name_and_address]    ## Obtain assembly instructions 

                str_instructions = '<para font="Courier" size="12">\n'
                for instruction in reversed(function_instructions):       ## For loop to display disassembled code
                    str_instructions += instruction + '\n' 
                str_instructions += '\n</para>'
                str_instructions = str_replace(str_instructions)

                p5 = Paragraph(str_instructions, styles['BodyText'])

                table_data = [[p4],[p5]]
                table = Table(table_data, colWidths=390, spaceBefore=10, spaceAfter=10, splitByRow=0)
                table.setStyle(TableStyle([('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
                                        ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
                                        ('BACKGROUND', (0, 0), (0, 0), colors.darkred)]))
                                        
                Story.append(table)
                if count != len(vul_path):              # Adding arrows to link the paths
                    str_arrow = Paragraph('<para align="center" size="15">\u2193</para>', styles['BodyText'])
                    Story.append(str_arrow)
                    count += 1

            Story.append(PageBreak())
        
        sink_num += 1
 
    return

def appendix(Story, data):
    
    ## Generate header

    heading = '<font face="Times"><b>Appendix</b></font>\n'
    heading = str_replace(heading)
    
    p_heading = Paragraph(heading, styles["Heading1"])
    Story.append(p_heading)
    Story.append(line)
    

    ## Printing out decompiled C code of the functions

    for decompiled_code in data:
        
        function_name = list(decompiled_code.keys())[0]
        code = decompiled_code[function_name]

        str_header = f'<para size="11" color="blue"><a name="{function_name}" /><b>{function_name}</b></para>'
        p_str_heading = Paragraph(str_header, styles["Heading2"])
        Story.append(p_str_heading)

        str = f'<para bgcolor="pink" font="Courier" size="8" borderpadding="4" leftindent="4">{code}</para>'
        str = str_replace(str)

        p3 = Paragraph(str, styles["BodyText"])

        Story.append(p3)
        Story.append(PageBreak())     


## First Page PDF layout

def FirstPage(canvas, doc):
    canvas.saveState()
    if path.exists(img_logo):
        canvas.drawImage(img_logo, 37, 315, width=3.9*cm, preserveAspectRatio=True, mask='auto')
    canvas.setFont('Helvetica-Bold',24)
    canvas.drawString(PAGE_WIDTH-460, PAGE_HEIGHT-40, 'FinjectRoute')
    canvas.setFont('Helvetica',12)
    canvas.drawString(PAGE_WIDTH-460, PAGE_HEIGHT-65, Title)
    canvas.setFont('Helvetica',10)
    canvas.drawString(PAGE_WIDTH-140, PAGE_HEIGHT-85, Date)
    canvas.line(40,750,550,750)
    canvas.setFont('Helvetica',8)
    canvas.drawString(2*cm, 1.5*cm, "Page %d \ %s" % (doc.page, pageinfo))
    canvas.restoreState()


## Second Page onwards PDF layout 

def LaterPages(canvas, doc):
    canvas.saveState()
    canvas.setFont('Helvetica',8)
    canvas.drawString(2*cm, 1.5*cm, "Page %d \ %s" % (doc.page, pageinfo))
    canvas.restoreState()


## Generate a PDF file

def generate_pdf(json_name):

    binary_name = json_name.split('.json')[0]
    file_name = path.join(folder_name, f'{binary_name}.pdf')
    doc = MyDocTemplate(file_name)
    Story = [Spacer(1,1.5*cm)]


    ## Table of contents style

    toc = TableOfContents()
    Story.append(Paragraph("<para size='16'><b>Table of contents</b><br /><br /><br /></para>", styles["BodyText"]))
    Story.append(toc)
    Story.append(PageBreak())
    toc.levelStyles = [
        ParagraphStyle(fontName='Times-Bold', fontSize=12, name='TOCHeading1', leftIndent=20, firstLineIndent=-20, spaceBefore=3, leading=6),
        ParagraphStyle(fontSize=9, name='TOCHeading2', leftIndent=40, firstLineIndent=-20, spaceBefore=3, leading=3),
        ParagraphStyle(fontSize=9, name='TOCHeading3', leftIndent=40, firstLineIndent=5, spaceBefore=3, leading=3)
    ]
    
    
    ## Obtaining JSON input
    
    json_file_path = path.join(json_folder, f'./{json_name}')
    with open(json_file_path ,'r') as f:
        data = load(f)
    
    
    ## Separating vulnerable and non-vulnerable information
   
    vulnerable_info = data['vulnerable']
    non_vulnerable_info = data['non-vulnerable']
    decompiled_code = data['function decompilations']
    

    ## Calling the functions
   
    if len(vulnerable_info) == 0 and len(non_vulnerable_info) == 0: # Check if there are vulnerabilities found, if not, a PDF report will not be generated 
        print(f'\u001b[32m**No vulnerable and non-vulnerable sink function(s) found for \'{binary_name}\', report not generated...\u001b[0m')
        return False
    elif len(vulnerable_info) == 0 and len(non_vulnerable_info) != 0:
        taint_graphs(Story, binary_name, non_vulnerable_info, 'non-vul') 
        taint_details(Story, non_vulnerable_info, 'non-vul')
    elif len(non_vulnerable_info) == 0 and len(vulnerable_info) != 0:
        taint_graphs(Story, binary_name, vulnerable_info, 'vul') 
        taint_details(Story, vulnerable_info, 'vul')
    else:
        taint_graphs(Story, binary_name, vulnerable_info, 'vul') 
        taint_graphs(Story, binary_name, non_vulnerable_info, 'non-vul')
        taint_details(Story, vulnerable_info, 'vul')
        taint_details(Story, non_vulnerable_info, 'non-vul')

    appendix(Story, decompiled_code)
    
    # for f in json_files:           ## for loop to remove all json files
        # remove(path.join(json_folder, f))
    

    ## Constructing the PDF document
    
    doc.multiBuild(Story, onFirstPage=FirstPage, onLaterPages=LaterPages)

    return True

# ======================== End of Functions ========================



# ============================= Start of programm ===================================

if len(json_files) != 0:
    folder_name = path.join(filepath, generate_folder.generate_folder())
    #folder_name = path.join(filepath, '../Output/PDFs/PDF_13Jul_1502')

    line = Drawing(100,1)
    line.add(Line(-0.3*cm, 0, 15.8*cm, 0))

    failure_count = 0
    success_count = 0
    zero_vul_count = 0

    print('Starting PDF report generation...\n')

    for i in range(len(json_files)):
        
        binary_name = json_files[i].split('.json')[0]
        date_time = datetime.now().strftime('%d-%b-%Y')


        ## Setting the data and title of PDF report

        Title = f'Report on \'{binary_name}\''
        Date = f'Date: {date_time}'
        pageinfo = f'Report on \'{binary_name}\' (FinjectRoute)'
        

        ## Generation of PDF (w/ console output on status of generation)    

        try:
            if generate_pdf(json_files[i]):
                print(f'\u001b[33mVulnerabilities/non-vulnerabilities found for \'{binary_name}\', report generated [{binary_name}.pdf] for {binary_name}...\u001b[0m')
                success_count += 1
            else:
                zero_vul_count += 1
        except KeyError:
            failure_count += 1
            print(f'\u001b[31mError generating report for \'{binary_name}\'... (Likely due to error in JSON structure)\u001b[0m')      
        except Exception:
            failure_count += 1
            print(f'\u001b[31mError generating report for \'{binary_name}\'...\u001b[0m')
            print_exc()
            print()
  
    # for f in graph_files:           ## for loop to remove all graph images
        # remove(path.join(graph_folder, f))

    if len(listdir(folder_name)) == 0:       ## removes folder if program successfully runs but no PDFs generated
        rmdir(folder_name)

    print('\nPDF report generation completed...\n')
    print('Summary of PDF generation:\n')
    print(f'Total number of binaries analysed: {len(json_files)}')
    print(f'\u001b[33mNumber of PDF(s) generated: {success_count}\u001b[0m')
    print(f'\u001b[31mNumber of PDF(s) failed to generate: {failure_count}\u001b[0m')
    print(f'\u001b[32mNumber of binary/binaries with no vulnerable and non-vulnerable sink function(s): {zero_vul_count}\u001b[0m\n')
else:
    print('No JSON data found...\nTerminating program...\n')
    
# ============================= End of programm ===================================