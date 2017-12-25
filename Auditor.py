import os.path
import sys
file_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.pardir))
if file_path not in sys.path:
    sys.path.insert(0, file_path) 
    
import dns.resolver
import re
import xlwt
import xlsxwriter

class whiteList:
    
    def __init__(self):
	self.vulnerablelist=["akamai.net","fastly.com","awsstatic.com","appspot.com","akamaiedge.net","s3.amazonaws.com"]
	self.likelyVulnerableList=["example","powerflexweb","anything","disney.go.com","facebook.com"]
	
    def readData(self,fileName):
        try:
            fHandle=open(fileName,"r")
            return fHandle
        except Exception as e:
            print "Exception Occured during opening a file with read mode. Exception message : ",str(e)
	     
    
    def checkVulnerable(self,data):
	if  self.vulnerablelist:
	    formatSet=0
	    for domain in  self.vulnerablelist:
		try:
		    if data[2]:
			if str(domain).strip().lower() in str(data[2]).strip().lower():
			    formatSet=1
		except Exception as e:
		    pass
		
		try:
		    if data[3]:
			if str(domain).strip().lower() in str(data[3]).strip().lower():
			    formatSet=1
		except Exception as e:
		    pass
	    return formatSet
	else:
	    return 0
    
    def checkOtherDomains(self,data):
	if  self.likelyVulnerableList:
	    formatSet=0
	    for domain in  self.likelyVulnerableList:
		try:
		    if data[0]:
			match=re.match(r'^(\*|\*\.|)'+str(domain)+"(\.com(\*|)|\.\*|\*|)$",str(data[0]).strip(),re.I|re.M)
			if match:
			    formatSet=1
		except Exception as e:
		    pass
	    return formatSet
	else:
	    return 0	
	    
            
    def getCNAME(self,fileContent):
        try:
            cname=[]
	    print "Finding Canonical Domain Name Process  Started"
            for line in fileContent:
                url=""
                match=re.match(r'(http:\/\/www\.|http:\/\/|^\.|\*\.|^)(.*.com|.*.net|.*.us|[a-zA-Z\.\*]+)(\/.*|$)',str(line),re.M|re.I)
                if match:
                    #url+=str(match.group(2))
		    url+=str(line).strip()
                    try:
                        address=""
                        qResult=dns.resolver.query(str(match.group(2)),"A")
                        for data in qResult:
                            address+=str(data.address)+" "
                        url+="##"+address
                    except Exception as e:
                        url+="##Address Not Found"
                    try:
			firstlayer=""
			bit=0
			try:
			    qResult=dns.resolver.query(str(match.group(2)),"CNAME")
			    for data in qResult:
				firstlayer=str(data.target)
				url+="##"+str(data.target)
			except Exception as e:
				url+="Not found"
				bit=1
			if bit == 0:
			    try:
				qResult=dns.resolver.query(str(firstlayer),"CNAME")
				for data in qResult:
				    url+="##"+str(data.target)
			    except Exception as e:
				    url+="##"   
			
		    except Exception as e:
			    pass
                    cname.append(url)  
	    print "Finding Canonical Domain Name Process  Finished"
            return cname
        except Exception as e:
            print "not found"
            return cname
        
    def updateExcelSheet(self,data):
        try:
	    print "Started Updating results in Excel File"
            book = xlsxwriter.Workbook('CNAME.xlsx')
	    book1 = xlsxwriter.Workbook('vluncnames.xlsx')
	    backgroundFormat=book.add_format()
	    vulbackgroundFormat=book1.add_format()
	    
	    backgroundFormat.set_bg_color('green')	
	    backgroundFormat.set_font_color('yellow') 
	    
	    vulbackgroundFormat.set_bg_color('green')	
	    vulbackgroundFormat.set_font_color('yellow') 	    
	    
	    
	    
	    highlightBackGroundFormat=book.add_format()	
	    highlightBackGroundFormat.set_bg_color('red')
	    
	    vulhighlightBackGroundFormat=book1.add_format()	
	    vulhighlightBackGroundFormat.set_bg_color('red')            	    
	    
	    highlightnonvBackGroundFormat=book.add_format()	
	    highlightnonvBackGroundFormat.set_bg_color('orange')
	    
	    vulhighlightnonvBackGroundFormat=book1.add_format()	
	    vulhighlightnonvBackGroundFormat.set_bg_color('orange')	    
	    
	    
	    vulnsheet1=book1.add_worksheet("vulnerable_Domain")
	    vulnsheet1.set_column("B:F",50)
	    vulnsheet1.write(1,1,"URL",vulbackgroundFormat)
	    vulnsheet1.write(1,2,"CNAME(First Layer)",vulbackgroundFormat)
	    vulnsheet1.write(1,3,"CNAME(Second Layer)",vulbackgroundFormat)
	    vulnsheet1.write(1,4,"IP Address",vulbackgroundFormat)	    
	    
            sheet1 = book.add_worksheet("URLwithCNAME")
	    sheet1.set_column("B:F",50)
            sheet1.write(1,1,"URL",backgroundFormat)
            sheet1.write(1,2,"CNAME(First Layer)",backgroundFormat)
	    sheet1.write(1,3,"CNAME(Second Layer)",backgroundFormat)
            sheet1.write(1,4,"IP Address",backgroundFormat)
            row=2
	    vulrow=2
            for key in data:
		#print key
                value=str(key).split('##')
		if self.checkVulnerable(value):
		    try:
			sheet1.write(row,1,value[0].decode('utf-8'),highlightBackGroundFormat)
			vulnsheet1.write(vulrow,1,value[0].decode('utf-8'),vulhighlightBackGroundFormat)
		    except Exception as e:
			pass
		    try:
			sheet1.write(row,2,value[2].decode('utf-8'),highlightBackGroundFormat)
			vulnsheet1.write(vulrow,2,value[2].decode('utf-8'),vulhighlightBackGroundFormat)
		    except Exception as e:
			pass
		    try:
			if value[3]:
			    sheet1.write(row,3,value[3].decode('utf-8'),highlightBackGroundFormat)
			    vulnsheet1.write(vulrow,3,value[3].decode('utf-8'),vulhighlightBackGroundFormat)
		    except Exception as e:
			pass
		    try:
			sheet1.write(row,4,value[1].decode('utf-8'),highlightBackGroundFormat)   
			vulnsheet1.write(vulrow,4,value[1].decode('utf-8'),vulhighlightBackGroundFormat)
			
		    except Exception as e:
			pass	
		    vulrow=vulrow+1
		else:
		    firstRuleMatch=re.match(r'^\*\..*',str(value[0]),re.I|re.M)
		    secondRuleMatch=re.match(r'.*\*$',str(value[0]),re.I|re.M)
		    if firstRuleMatch or secondRuleMatch:
			try:
			    sheet1.write(row,1,value[0].decode('utf-8'),highlightnonvBackGroundFormat)
			    vulnsheet1.write(vulrow,1,value[0].decode('utf-8'),vulhighlightnonvBackGroundFormat)
			except Exception as e:
			    pass
			try:
			    sheet1.write(row,2,value[2].decode('utf-8'))
			    vulnsheet1.write(vulrow,2,value[2].decode('utf-8'))
			except Exception as e:
			    pass
			try:
			    if value[3]:
				sheet1.write(row,3,value[3].decode('utf-8'))
				vulnsheet1.write(vulrow,3,value[3].decode('utf-8'))
			except Exception as e:
			    pass
			try:
			    sheet1.write(row,4,value[1].decode('utf-8'))  
			    vulnsheet1.write(vulrow,4,value[2].decode('utf-8'))
			except Exception as e:
			    pass	
			vulrow=vulrow+1
		    elif self.checkOtherDomains(value):
			try:
			    sheet1.write(row,1,value[0].decode('utf-8'),highlightnonvBackGroundFormat)
			    vulnsheet1.write(vulrow,1,value[0].decode('utf-8'),vulhighlightnonvBackGroundFormat)
			except Exception as e:
			    pass
			try:
			    sheet1.write(row,2,value[2].decode('utf-8'))
			    vulnsheet1.write(vulrow,2,value[2].decode('utf-8'))
			except Exception as e:
			    pass
			try:
			    if value[3]:
				sheet1.write(row,3,value[3].decode('utf-8'))
				vulnsheet1.write(vulrow,3,value[3].decode('utf-8'))
			except Exception as e:
			    pass
			try:
			    sheet1.write(row,4,value[1].decode('utf-8')) 
			    vulnsheet1.write(vulrow,4,value[2].decode('utf-8'))
			except Exception as e:
			    pass	
			vulrow=vulrow+1
		    else:
			try:
			    sheet1.write(row,1,value[0].decode('utf-8'))
			except Exception as e:
			    pass
			try:
			    sheet1.write(row,2,value[2].decode('utf-8'))
			except Exception as e:
			    pass
			try:
			    if value[3]:
				sheet1.write(row,3,value[3].decode('utf-8'))
			except Exception as e:
			    pass
			try:
			    sheet1.write(row,4,value[1].decode('utf-8'))   
			except Exception as e:
			    pass				
		row=row+1
	    book.close() 
	    book1.close()
	    print "Finished Updating results in Excel File"
        except Exception as e:
            print "Error occured while updating values in Excel sheet.Error message : ",str(e)
	    
    def process(self,fileName):
	fileContent=self.readData(fileName)
	cnames=self.getCNAME(fileContent)
	self.updateExcelSheet(cnames)
        
if __name__ == '__main__':
    object=whiteList()
    object.process('sample.txt')