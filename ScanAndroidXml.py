#!/usr/bin/python3
import re
from traceback import print_tb
import requests
import sys
import os
from os import path

from calendar import c
from xml.dom import minidom

# parse an xml file by name


def isUniversalAccessFromFileUrlEnabled(exported_components):
	
	flag=0
	for i in exported_components:
		i = i.replace(".","/")
		filepath = pwd+"/sources/"+i+".java"
		with open(filepath,errors='ignore') as f:
			f2 = f.read()
			setAllowUniversalAccessFromFileURLs_enabled =  [_.start() for _ in re.finditer('setAllowUniversalAccessFromFileURLs',f2)]
			
			if len(setAllowUniversalAccessFromFileURLs_enabled)>0:
				start_ind = setAllowUniversalAccessFromFileURLs_enabled[-1]
				if f2[start_ind+36:start_ind+40]=="true":
					writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- isUniversalAccessFromFileUrlEnabled is set to True which make attacker able to access internal private Files </p>" )
					print("vulnerability Found Guys2")
					f=1
				else:
					writePassResults(filename," <p style=\"color:green;\"> <br>[Info] --- Exported Component :"+ i +" is not Vulnerable to isUniversalAccessFromFileUrlEnabled vulnerability </p>")
					print("all clear2")
	if flag==0:
		writePassResults(filename," <p style=\"color:green;\"> <span style='border: 9px solid white'>[Info] --- None of the exported acitivity have setUniversalAccessFromFileUrlEnabled set as True </span> </p> ")


def isJavascriptEnabled(exported_components):
	flag=0
	
	for i in exported_components:
		i = i.replace(".","/")
		filepath = pwd+"/sources/"+i+".java"
		with open(filepath,errors='ignore') as f:
			f2 = f.read()
			java_script_enabled = [_.start() for _ in re.finditer('setJavaScriptEnabled',f2)]

			if len(java_script_enabled)>0:
				start_ind = java_script_enabled[-1]
				if f2[start_ind+21:start_ind+25]=="true":
					writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- JavaScriptEnabled to True which make javascript file can execute from attacker </p>" )
					print("vulnerability Found Guys")
				else:
					writePassResults(filename,"<br> <p style=\"color:green;\"> [Info] --- Exported Component :"+ i +" is not Vulnerable to javaScriptEnabled vulnerability</p>")
					print("all clear")
	if flag==0:
		writePassResults(filename,"<br> <p style=\"color:green;\"> [Info] --- None of the exported acitivity have javaScriptEnabled set as True </p>")

				
            
def find_exported_component():
	filepath = pwd+"/"+"resources"+"/"+manifestFile
	print("filepath------>",filepath,filename,pwd)
	mydoc = minidom.parse(filepath)
	activities = mydoc.getElementsByTagName('activity')

	exported_class = []
	for i in range(len(activities)):
		try:
			temp = activities[i].attributes['android:exported'].value
			print("Found a exported component: ",activities[i].attributes['android:name'].value)
			exported_class.append(activities[i].attributes['android:name'].value)
		except:
			print("Not a exported component ",activities[i].attributes['android:name'].value)
		finally:
			print("----------------")  
	writePassResults(filename,"<br> <b> <h3 style='text-align:center'>Webview Vulnerability Checks </h3></b> ")		  
	isJavascriptEnabled(exported_class)
	isUniversalAccessFromFileUrlEnabled(exported_class)
	print(exported_class)

# Usage python lime.py <apkfile>
# fireBaseTest method will check for firebase url in /res/values/strings.xml
def fireBaseTest(filename, stringsFile):
	#Get Firebase URL 
	firebaseURL=""
	#writeResults(filename,"</br>[Info] --- Checking for firebase URLs")
	# for Strings.xml file 
	stringsFile=pwd+"/"+"resources"+stringsFile
	print(stringsFile)
	writePassResults(filename,"<br> <b><h3 style='text-align:center'>Firebase Checks</h3></b> ")
	try:
		#writeResults(filename,"</br>[Info]---Strings.xml file Location:"+ stringsFile)
		with open(stringsFile, errors='ignore') as f:
			f1=f.read()
			print("File Opened SuccessFully")
			searchObj=re.findall(r'https://.*.firebaseio.com', f1)
			i=len(searchObj)
			if(i !=0):
				while i > 0:
				#print(i)
					i=i-1
					firebaseURL=searchObj[i]
					#writeResults(filename,"</br>[Info] --- Firebase URL found " + firebaseURL)
					firebaseURL=firebaseURL+"/.json"
					#writeResults(filename,"</br>[Info] --- Accessing "+ firebaseURL)
					req=requests.get(firebaseURL)
					if req.status_code == 200:
						writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- Firebase <a href='"+firebaseURL+"'>"+firebaseURL+"</a> is publicly accessible </p>" )
						writeResults(filename,"</br><button type='button' onclick='alert(JSON.stringify("+req.text+"))'> Show Response from " + firebaseURL+"</button> <br>Strings.xml file Location:"+ stringsFile)
					else:
						writePassResults(filename,"<p style=\"color:green;\"> <br>[Info] --- Not Vulnerable. Strings.xml file Location:"+ stringsFile+"<br> Response from <a href='"+firebaseURL+"'>" + firebaseURL +"</a> </br>"+ req.text+"</p>")
			else:
				writePassResults(filename,"</br> <p style=\"color:green;\"> [Info] --- App doesn't have firebase URLs </p>")
	except IOError:
		writeResults(filename,"</br> Strings.xml not accessible")
						
def network_security_config_Test(filename,nscFile):
	#writeResults(filename,"</br>[Info] --- Network security config check is in progress")
	stringsFile=pwd+"/"+"resources"+nscFile
	writePassResults(filename,"<br> <b><h3 style='text-align:center'>Network Security Config Checks</h3></b>")
	try:
		with open(stringsFile, errors='ignore') as f:
			#writeResults(filename,"</br>network_security_config.xml file Location:"+ stringsFile)
			fData=f.read()
		# Search for <certificates src="user"/>
			searchObj=re.search(r'<certificates.*src.*user.*>', fData, re.M|re.I)
			if searchObj:
				writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- Misconfigured network_security_config.xml. \n Found  "+searchObj.group()+" in network_security_config.xml which leads to MITM in Android devices API24 or above.</br>Found &lt;certificates src=\"user\" /&gt; in network_security_config.xml</p>network_security_config.xml file Location:"+ stringsFile)
			else:
				writePassResults(filename,"</br><p style=\"color:green;\"> [Info] --- Not found &lt;certificates src=\"user\" /&gt; in network_security_config.xml </br>network_security_config.xml file Location:"+ stringsFile+"</p>")
		# Search for <certificates src="@raw/*"/>
			searchObj=re.search(r'<certificates.*src.*raw.*>', fData, re.M|re.I)
			if searchObj:
				writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- Misconfigured network_security_config.xml. \n Found  "+searchObj.group()+" in network_security_config.xml which leads to MITM in Android devices API24 or above.</br>Found &lt;certificates src=\"@raw/*\"/&gt; in network_security_config.xml</p>network_security_config.xml file Location:"+ stringsFile)
			else:
				writePassResults(filename,"</br> <p style=\"color:green;\"> [Info] --- Not found &lt;certificates src=\"@raw/*\"/&gt; in network_security_config.xml</br>network_security_config.xml file Location:"+ stringsFile+"</p>")
		# Search for ClearTextTraffic
			searchObj=re.search(r'<domain-config.*cleartextTrafficPermitted.*true.*>', fData, re.M|re.I)
			if searchObj:
				writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- Misconfigured network_security_config.xml. \n Found  "+searchObj.group()+" in network_security_config.xml which leads to MITM in Android devices API24 or above</p> </br>network_security_config.xml file Location:"+ stringsFile)
			else:
				writePassResults(filename,"</br> <p style=\"color:green;\"> [Info] --- Not found &lt;domain-config cleartextTrafficPermitted=\"true\"&gt;  in network_security_config.xml</br>network_security_config.xml file Location:"+ stringsFile+"</p>")
	except IOError:
		writePassResults(filename,"</br> <p style=\"color:green;\"> App doesn't have network_security_config.xml </p>")
	
def getDeepLinks():
	writePassResults(filename,"</br> <b> <h3 style='text-align:center'>Custom URL Check </h3></b>")
	# for AndroidManifest.xml file 
	f1=pwd+"/"+"resources"+"/"+manifestFile
	writePassResults(filename,"<p style=\"color:orange;\"> [Info]---AndroidManifest.xml file Location: "+ f1+"</p>")
	with open(f1, errors='ignore') as f:
		f2=f.read()
		i= f2.count("<data android:scheme")	
		searchObj1=re.findall(r'<data android:host=(.*)', f2)
		j=len(searchObj1)
		if(j !=0):
			while j > 0:
				j=j-1
				scheme1=re.search(r'android:scheme="(.*)"', searchObj1[j], re.M|re.I)
				if scheme1:
					writePassResults(filename,"</br>scheme: "+ scheme1.group(1))
					host1=searchObj1[j].replace(scheme1.group(),"")
					host2=re.search(r'"(.*)"', host1, re.M | re.I)
					if host2:
						writePassResults(filename,"<p style=\"color:orange;\"> host: " + host2.group(1)+"</br>Deeplink: " + scheme1.group(1) + "://"+ host2.group(1)+"</p>")
					else:
						writePassResults(filename,"<p style=\"color:orange;\"> No host found</br>Deeplink: "+ scheme1.group(1) + "://</p>")
				else:
					host3=searchObj1[j].replace('"','')
					host4=host3.replace('/>','')
					writePassResults(filename,"<p style=\"color:orange;\"> no scheme found</br>host: " + host4 +"</br>Deeplink: " + "://" + host4+"</p>")
		
		searchObj=re.findall(r'<data android:scheme=(.*)' , f2)
		i=len(searchObj)
		if(i !=0):
			while i > 0:
				i=i-1
				host=re.search(r'android:host="(.*)"' , searchObj[i], re.M|re.I)
				if host:
					writePassResults(filename,"<p style=\"color:orange;\">host: " + host.group(1)+"</p>")
					scheme1=searchObj[i].replace(host.group(),"")
					scheme=re.search(r'"(.*)"' , scheme1, re.M|re.I)
					if scheme:				
						writePassResults(filename,"<p style=\"color:orange;\"> scheme: " + scheme.group(1)+"</br>Deeplink: " + scheme.group(1)+"://"+host.group(1)+"</p>")
						scheme=scheme1.replace(scheme.group(),"")
					else:
						writePassResults(filename,"<p style=\"color:orange;\">  No Scheme found</br>Deeplink: "+ "://"+ host.group(1)+"</p>")
				else:
					scheme=searchObj[i].replace('"','')
					scheme=scheme.replace('/>','')
					writePassResults(filename,"<p style=\"color:orange;\"> no host found</br>scheme: " + scheme +"</br>Deeplink: " + scheme + ":// </p>")
				
			
def isDebuggableOrBackup():
	find_exported_component()
	f1=pwd+"/"+"resources"+"/"+manifestFile
	with open(f1, errors='ignore') as f:
		f2=f.read()
		searchObj=re.search(r'android:debuggable="true"' , f2, re.M|re.I)
		if searchObj:
			writeResults(filename,"<p style=\"color:red;\">[Vulnerability] ---Android debuggable. \n Found android:debuggable=true in AndroidManifest.xml file</p>")
		else:
			writePassResults(filename,"</br><b><h3 style='text-align:center'>android:debuggable Check </h3></b> <br><p style=\"color:green;\">[Info] --- android:debuggable not found</p>")
		searchObj1=re.search(r'android:allowBackup="true"' , f2, re.M|re.I)
		searchObj2=re.search(r'android:allowBackup="false"' , f2, re.M|re.I)
		if searchObj1:
			writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- Android backup vulnerability. \n Found android:allowBackup=true in AndroidManifest.xml file</p>")
		elif searchObj2:	
			writePassResults(filename,"</br><b><h3 style='text-align:center'>android:allowBackup Check </h3></b></br> <p style=\"color:green;\">[Info] --- android:allowBackup=\"false\" found </p>")
		else:
			writeResults(filename,"<p style=\"color:red;\">[Vulnerability] --- Android backup vulnerability . \n Not found android:allowbackup=true, default value is true, in AndroidManifest.xml file</p>")
			


def writeResults(filename,msg):
	f=open(resultsHtml,"a")
	f.write(msg)
	f.close()
	
def writePassResults(filename,msg):
	f=open(resultsHtmlTemp,"a")
	f.write(msg)
	f.close()
	
apkfile = sys.argv[-1]
# Get file extension .apk 
filename, file_extension = os.path.splitext(apkfile)
pwd=os.getcwd()
stringsFile="/res/values/strings.xml"
nscFile="/res/xml/network_security_config.xml"
manifestFile="AndroidManifest.xml"
resultsHtml=filename+".html"
resultsHtmlTemp=filename+"Temp.html"
head="<!DOCTYPE html><html><head><style>table {  font-family: arial, sans-serif;  border-collapse: collapse;  width: 100%;}	td, th {	border: 1px solid #dddddd;	text-align: left;	padding: 8px;	}	tr:nth-child(even) {	background-color: #b99aff;	}	body {background-color: #1b1e23} p  {color: white;} h1  {color: white;} h2  {color: white;} h3  {color: white;} h4  {color: white;}</style>	</head>	<body>"
endhtml="</body> </html>"
writeResults(filename, head +"<h3>This tool analyze Android app to find vulnerabilities in AndroidManifest.xml, network_security_config.xml, Firebase URLs from strings.xml and Webview Vulnerabilities </br>This tool also shows Deeplinks used in Android app  </br> Analysis results of <u>"+apkfile+"</u></h3>")
if file_extension == ".apk":
	#Decompile APK file 
	print("Please wait while I am analyzing Android app" + apkfile)
	if path.exists(resultsHtml):
		os.remove(resultsHtml)
		writeResults(filename, head +"<h3>This tool analyze Android app to find vulnerabilities in AndroidManifest.xml, network_security_config.xml, Firebase URLs from strings.xml and Webview Vulnerabilities </br>This tool also shows Deeplinks used in Android app  </br> Analysis results of <u>"+apkfile+"</u></h3>")	
	os.system('jadx -d ./ "' +apkfile+'"')
	# os.system('java -jar apktool.jar d -q "' + apkfile +'"')
	isDebuggableOrBackup()
	network_security_config_Test(filename, nscFile)
	fireBaseTest(filename, stringsFile)
	getDeepLinks()
	try:
		f11=open(resultsHtmlTemp, "r")
		writeResults(filename, "<h2 style='text-align:center'>Pass cases</h2>"+f11.read() + endhtml)
		f11.close()
		os.remove(resultsHtmlTemp)
	except IOError:
		writeResults(filename,endhtml)
	print("Results are printed in "+pwd+"\\"+resultsHtml)
# if file extension is not .apk
else:
	writeResults(filename,"</br>Please use apk file only")