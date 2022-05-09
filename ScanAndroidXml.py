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
# def findOnRecieveSSL():
def checkSSLSecurityCheckInWebview(sample):
	writePassResults(filename," <b><h3 style='text-align:center'>SSL Implementation for Webview Check</h3></b> </br> ")
	if len(sample)==0:
		return
	ff=0	
	for j in range(len(sample)):
		if ff==1:
			break	
		temp = sample[j].split(".")
		flag = 0
		path = pwd+"/sources/"
		# print("sample----",sample)
		for i in range(len(temp)-1):
			path+=temp[i]
			path+="/"
		print("path-----",path)
		files = []
		try:	
			files = os.listdir(path)
			ff=1
		except:
			pass	
		for i in files:
			file = path+i 
			if os.path.isfile(file):
				with open(file,errors='ignore') as f:
					f2 = f.read()
					onReceivedSSlError =  [_.start() for _ in re.finditer('onReceivedSslError',f2)]
					if(len(onReceivedSSlError))>0:
						proceed =  [_.start() for _ in re.finditer('.proceed()',f2)]
						if len(proceed)>0:
							writeResults(filename,"<ul> <li> <p style=\"color:red;\"><b>[Vulnerability]</b> --- <b>SSL Security Vulnerable Found</b> DO NOT use 'handler.proceed();' inside those methods in extended 'WebViewClient', which allows the connection even if the SSL Certificate is invalid (MITM Vulnerability). </p> </li> </ul>")
							flag=1
							print("HEREEE I AMMMM")
							writeResults(filename,"<hr style='border-top: dotted 3px' />")
							break 
	print("FLAG__",flag)
	if flag==0:
		writePassResults(filename,"<ul> <li> <p style=\"color:green;\"> <span style='border: 9px solid white'><b>[Info]</b> ---  </span> SSL Implementation for WebViewClient or WebView found good, Did not detect critical usage of WebViewClient (MITM Vulnerability). </p> </li> </ul>")
		writePassResults(filename,"<hr style='border-top: dotted 3px' />")



webview_f = [0]
def isUniversalAccessFromFileUrlEnabled(exported_components):
	
	flag=0
	for i in exported_components:
		i = i.replace(".","/")
		filepath = pwd+"/sources/"+i+".java"
		if os.path.isfile(filepath):
			with open(filepath,errors='ignore') as f:
				f2 = f.read()
				setAllowUniversalAccessFromFileURLs_enabled =  [_.start() for _ in re.finditer('setAllowUniversalAccessFromFileURLs',f2)]
				
				if len(setAllowUniversalAccessFromFileURLs_enabled)>0:
					start_ind = setAllowUniversalAccessFromFileURLs_enabled[-1]
					if f2[start_ind+36:start_ind+40]=="true":
						writeResults(filename,"<ul> <li> <p style=\"color:red;\"><b>[Warning]</b> ---  Found 'setAllowFileAccess(true)' or not set(enabled by default) in WebView. The attackers could inject malicious script into WebView and exploit the opportunity to access local resources. This can be mitigated or prevented by disabling local file system access. (It is enabled by default) Note that this enables or disables file system access only. Assets and resources are still accessible using file:///android_asset and file:///android_res. The attackers can use WebView.loadUrl('file:///data/data/[Your_Package_Name]/[File]'); to access app's local file.</p> </li> </ul>" )
						flag=1
						break
					else:
						pass
	if flag==0:
		writePassResults(filename,"<ul> <li> <p style=\"color:green;\"> <span style='border: 9px solid white'><b>[Info]</b> --- </span> None of the component have setUniversalAccessFromFileUrlEnabled set as True  </p> </li> </ul>")
		writePassResults(filename,"<hr style='border-top: dotted 3px' />")
	else:	

		if webview_f[0]==2:
			writePassResults(filename,"<ul> <li> <p style=\"color:green;\"> No Webview check Passed </p> </li> </ul>")
		else:
			writePassResults(filename,"<ul> <li> <p style=\"color:green;\"><b>[Info]</b> None of the component have 'setAllowFileAccess' configuration as eneabled </p> </li> </ul>")	
		writeResults(filename,"<hr style='border-top: dotted 3px' />")
		writePassResults(filename,"<hr style='border-top: dotted 3px' />")
def isJavaScriptInterface(exported_components):
	
	flag=0
	print("EXPORTED COMPO********",exported_components)
	for i in exported_components:
		i = i.replace(".","/")
		filepath = pwd+"/sources/"+i+".java"

		print(filepath)
		if os.path.isfile(filepath):
			with open(filepath,errors='ignore') as f:
				f2 = f.read()
				setAllowUniversalAccessFromFileURLs_enabled =  [_.start() for _ in re.finditer('addJavascriptInterface',f2)]
				
				if len(setAllowUniversalAccessFromFileURLs_enabled)>0:
					writeResults(filename,"<ul> <li> <p style=\"color:red;\"><b>[Vulnerability]</b> ---  <Remote Code Execution><#CVE-2013-4710#> WebView RCE Vulnerability Checking: Found a critical WebView 'addJavascriptInterface' vulnerability. This method can be used to allow JavaScript to control the host application. This is a powerful feature, but also presents a security risk for applications targeted to API level JELLY_BEAN(4.2) or below, because JavaScript could use reflection to access an injected object's public fields. Use of this method in a WebView containing untrusted content could allow an attacker to manipulate the host application in unintended ways, executing Java code with the permissions of the host application. </p> </li> </ul>")
					flag=1
					break
					# else:
					# 	pass
	if flag==0:
		writePassResults(filename,"<ul> <li> <p style=\"color:green;\"><span style='border: 9px solid white'><b>[Info]</b> --- </span>Application is secure from java to javascript Interface vulnerability  </p> </li> </ul>")
	else:
		webview_f[0] +=1

def isJavascriptEnabled(exported_components):
	flag=0
	
	for i in exported_components:
		i = i.replace(".","/")
		filepath = pwd+"/sources/"+i+".java"
		if os.path.isfile(filepath):
			with open(filepath,errors='ignore') as f:
				f2 = f.read()
				java_script_enabled = [_.start() for _ in re.finditer('setJavaScriptEnabled',f2)]

				if len(java_script_enabled)>0:
					start_ind = java_script_enabled[-1]
					if f2[start_ind+21:start_ind+25]=="true":
						flag=1
						writeResults(filename,"<ul> <li> <p style=\"color:red;\"><b>[Warning]</b> --- <b> Found 'setJavaScriptEnabled(true)' in WebView </b>, which could exposed to potential XSS attacks. </p> </li> </ul>" )
						break
					else:
						pass
	if flag==0:
		writePassResults(filename,"<ul> <li> <p style=\"color:green;\"><b>[Info]</b> --- None of the exported acitivity have javaScriptEnabled set as True </p> </li> </ul>")
	else:
		webview_f[0] = +1			
            
def find_exported_component():
	filepath = pwd+"/"+"resources"+"/"+manifestFile
	print("filepath------>",filepath,filename,pwd)
	mydoc = minidom.parse(filepath)
	writePassResults(filename," <b><h3 style='text-align:center'>Exported Components</h3></b> ")
	activities = mydoc.getElementsByTagName('activity')
	services = mydoc.getElementsByTagName('service')
	receiver = mydoc.getElementsByTagName('receiver')
	
	exported_class = []
	all_class = []
	for i in range(len(activities)):
		try:
			temp = activities[i].attributes['android:exported'].value
			print("Found a exported component: ",activities[i].attributes['android:name'].value)
			writePassResults(filename,"<ul> <li> <p style=\"color:orange;\"><b>[Info]</b> --- Exported Activities:" + activities[i].attributes['android:name'].value +"</p> </li> </ul>")
			exported_class.append(activities[i].attributes['android:name'].value)
		except:
			pass
		
		all_class.append(activities[i].attributes['android:name'].value)	
	for i in range(len(services)):
		try:
			temp = services[i].attributes['android:exported'].value
			print("Found a exported component: ",services[i].attributes['android:name'].value)
			writePassResults(filename,"<ul> <li> <p style=\"color:orange;\"><b>[Info]</b> --- Exported Services:" + services[i].attributes['android:name'].value +"</p> </li> </ul>")
			exported_class.append(services[i].attributes['android:name'].value)
		except:
			pass
		
		all_class.append(services[i].attributes['android:name'].value)	
	for i in range(len(receiver)):
		try:
			temp = receiver[i].attributes['android:exported'].value
			print("Found a exported component: ",receiver[i].attributes['android:name'].value)
			writePassResults(filename,"<ul> <li> <p style=\"color:orange;\"><b>[Info]</b> --- Exported Receivers:" + receiver[i].attributes['android:name'].value +"</p> </li> </ul>")
			exported_class.append(receiver[i].attributes['android:name'].value)
		except:
			print("Not a exported component ",receiver[i].attributes['android:name'].value)
		
		all_class.append(receiver[i].attributes['android:name'].value)					

	writePassResults(filename,"<hr style='border-top: dotted 3px' />")		
	writePassResults(filename," <b> <h3 style='text-align:center'>Webview Vulnerability Checks </h3></b> ")		
	isJavaScriptInterface(all_class)  
	isJavascriptEnabled(all_class)
	isUniversalAccessFromFileUrlEnabled(all_class)
	checkSSLSecurityCheckInWebview(all_class)
	print(exported_class)

# Usage python lime.py <apkfile>
# fireBaseTest method will check for firebase url in /res/values/strings.xml
def fireBaseTest(filename, stringsFile):
	flag = 0
	#Get Firebase URL 
	firebaseURL=""
	#writeResults(filename,"</br>[Info] --- Checking for firebase URLs")
	# for Strings.xml file 
	stringsFile=pwd+"/"+"resources"+stringsFile
	print(stringsFile)
	writePassResults(filename," <b><h3 style='text-align:center'>Firebase Checks</h3></b> ")
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
						flag = 1
						writeResults(filename,"<ul> <li> <p style=\"color:red;\"><b>[Vulnerability]</b> --- Firebase <a href='"+firebaseURL+"'>"+firebaseURL+"</a> is publicly accessible </p> </li> </ul>" )
						writeResults(filename,"<ul> <li> <p style=\"color:red;\"> </br><button type='button' onclick='alert(JSON.stringify("+req.text+"))'> Show Response from " + firebaseURL+"</button> <br>Strings.xml file Location:"+ stringsFile+"</p> </li> </ul>")
					else:
						writePassResults(filename,"<ul> <li> <p style=\"color:green;\"><b>[Info]</b> --- Not Vulnerable. Strings.xml file Location:"+ stringsFile+"<br> Response from <a href='"+firebaseURL+"'>" + firebaseURL +"</a> </br>"+ req.text+"</p> </li> </ul>")
			else:
				writePassResults(filename," <ul> <li> <p style=\"color:green;\"><b>[Info]</b> --- App doesn't have firebase URLs </p> </li> </ul>")
		writePassResults(filename,"<hr style='border-top: dotted 3px' />")
		if flag==1:
			writeResults(filename,"<hr style='border-top: dotted 3px' />")	
	except IOError:
		writeResults(filename,"<ul> <li>  Strings.xml not accessible </li> </ul>")
		writePassResults(filename,"<hr style='border-top: dotted 3px' />")
		if flag==1:
			writeResults(filename,"<hr style='border-top: dotted 3px' />")
						
def network_security_config_Test(filename,nscFile):
	flag = 0
	#writeResults(filename,"</br>[Info] --- Network security config check is in progress")
	stringsFile=pwd+"/"+"resources"+nscFile
	writePassResults(filename," <b><h3 style='text-align:center'>Network Security Config Checks</h3></b>")
	try:
		with open(stringsFile, errors='ignore') as f:
			#writeResults(filename,"</br>network_security_config.xml file Location:"+ stringsFile)
			fData=f.read()
		# Search for <certificates src="user"/>
			searchObj=re.search(r'<certificates.*src.*user.*>', fData, re.M|re.I)
			if searchObj:
				writeResults(filename,"<ul> <li> <p style=\"color:red;\"><b>[Vulnerability]</b> --- Misconfigured network_security_config.xml. \n Found  "+searchObj.group()+" in network_security_config.xml which leads to MITM in Android devices API24 or above.</br>Found &lt;certificates src=\"user\" /&gt; in network_security_config.xml </br> network_security_config.xml file Location:"+ stringsFile+"</p> </li> </ul>")
				flag = 1
			else:
				writePassResults(filename,"<ul> <li> <p style=\"color:green;\"><b>[Info]</b> --- Not found &lt;certificates src=\"user\" /&gt; in network_security_config.xml </br>network_security_config.xml file Location:"+ stringsFile+"</p> </li> </ul>")
		# Search for <certificates src="@raw/*"/>
			searchObj=re.search(r'<certificates.*src.*raw.*>', fData, re.M|re.I)
			if searchObj:
				flag =1
				writeResults(filename,"<ul> <li> <p style=\"color:red;\"><b>[Vulnerability]</b> --- Misconfigured network_security_config.xml. \n Found  "+searchObj.group()+" in network_security_config.xml which leads to MITM in Android devices API24 or above.</br>Found &lt;certificates src=\"@raw/*\"/&gt; in network_security_config.xml </br> network_security_config.xml file Location:"+ stringsFile+"</p> </li> </ul>")
			else:
				writePassResults(filename,"<ul> <li>  <p style=\"color:green;\"><b>[Info]</b> --- Not found &lt;certificates src=\"@raw/*\"/&gt; in network_security_config.xml</br>network_security_config.xml file Location:"+ stringsFile+"</p> </li> </ul>")
		# Search for ClearTextTraffic
			searchObj=re.search(r'<domain-config.*cleartextTrafficPermitted.*true.*>', fData, re.M|re.I)
			if searchObj:
				flag =1
				writeResults(filename,"<ul> <li> <p style=\"color:red;\"><b>[Vulnerability]</b> --- Misconfigured network_security_config.xml. \n Found  "+searchObj.group()+" in network_security_config.xml which leads to MITM in Android devices API24 or above </br>network_security_config.xml file Location:"+ stringsFile+"</p> </li> </ul>")
			else:
				writePassResults(filename,"<ul> <li>  <p style=\"color:green;\"><b>[Info]</b> --- Not found &lt;domain-config cleartextTrafficPermitted=\"true\"&gt;  in network_security_config.xml</br>network_security_config.xml file Location:"+ stringsFile+"</p> </li> </ul>")
		writePassResults(filename,"<hr style='border-top: dotted 3px' />")
		if flag==1:
			writeResults(filename,"<hr style='border-top: dotted 3px' />")
	except IOError:
		writePassResults(filename," <ul> <li> <p style=\"color:green;\"> App doesn't have network_security_config.xml </p> </li> </ul>")
		writePassResults(filename,"<hr style='border-top: dotted 3px' />")
		if flag==1:
			writeResults(filename,"<hr style='border-top: dotted 3px' />")
	
def getDeepLinks():
	writePassResults(filename," <b> <h3 style='text-align:center'>Custom URL Check </h3></b>")
	# for AndroidManifest.xml file 
	f1=pwd+"/"+"resources"+"/"+manifestFile
	writePassResults(filename,"<ul> <li> <p style=\"color:orange;\"><b>[Info]</b>---AndroidManifest.xml file Location: "+ f1+"</p> </li> </ul>")
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
	flag = 0
	find_exported_component()
	f1=pwd+"/"+"resources"+"/"+manifestFile
	with open(f1, errors='ignore') as f:
		f2=f.read()
		searchObj=re.search(r'android:debuggable="true"' , f2, re.M|re.I)
		if searchObj:
			writeResults(filename,"<ul> <li> <p style=\"color:red;\"><b>[Vulnerability]</b> --- Android Debug Mode Checking: DEBUG mode is ON(android:debuggable='true') in AndroidManifest.xml. This is very dangerous. The attackers will be able to sniffer the debug messages by Logcat. Please disable the DEBUG mode if it is a released application</p> </li> </ul>")
			flag = 1
		else:
			writePassResults(filename,"<b><h3 style='text-align:center'>android:debuggable Check </h3></b> <ul> <li> <p style=\"color:green;\">[Info] --- android:debuggable not found</p> </li> </ul>")
		searchObj1=re.search(r'android:allowBackup="true"' , f2, re.M|re.I)
		searchObj2=re.search(r'android:allowBackup="false"' , f2, re.M|re.I)
		if searchObj1:
			writeResults(filename,"<ul> <li> <p style=\"color:red;\"><b>[Vulnerability]</b> --- Android backup vulnerability. ADB Backup is ENABLED for this app. ADB Backup is a good tool for backing up all of your files. If it's open for this app, people who have your phone can copy all of the sensitive data for this app in your phone. The sensitive data may include lifetime access token, username or password, etc.</p> </li> </ul>")
			flag = 1
		elif searchObj2:	
			writePassResults(filename,"<ul> <li> <b><h3 style='text-align:center'>android:allowBackup Check </h3></b></br> <p style=\"color:green;\">[Info] --- android:allowBackup=\"false\" found </p> </li> </ul>")
		else:
			flag = 1
			writeResults(filename,"<ul> <li> <p style=\"color:red;\"><b>[Vulnerability]</b> --- Android backup vulnerability. ADB Backup is ENABLED for this app (default: ENABLED). ADB Backup is a good tool for backing up all of your files. If it's open for this app, people who have your phone can copy all of the sensitive data for this app in your phone. The sensitive data may include lifetime access token, username or password, etc.</p> </li> </ul>")

	if flag==1:	
		writeResults(filename,"<hr style='border-top: dotted 3px' />")	
	writePassResults(filename,"<hr style='border-top: dotted 3px' />")
	

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
head="<!DOCTYPE html><html><head><style>table {  font-family: arial, sans-serif;  border-collapse: collapse;  width: 100%;}	td, th {	border: 1px solid #dddddd;	text-align: left;	padding: 8px;	}	tr:nth-child(even) {	background-color: #b99aff;	}	body {background-color: white;   margin-top: 0px; } p  {color: black;} h1  {color: black;} h2  {color: black;} h3  {color: black;} h4  {color: black;}  div { background-color: #FBB117; height: 70px; padding-top:10px; padding-bottom:7px; margin-left:0px; } </style> </head>	<body>"
endhtml="</body> </html>"
writeResults(filename, head +"<div> <h1 style='text-align:center '>Android App Scanner </h1> </div> </br>  <h3 style='text-align:center'> Analysis results of "+apkfile+"</h3> ")
if file_extension == ".apk":
	#Decompile APK file 
	print("Please wait while I am analyzing Android app" + apkfile)
	if path.exists(resultsHtml):
		os.remove(resultsHtml)
		writeResults(filename, head +" <div><h1 style='text-align:center'>Android App Scanner </h1> </div></br> <u> <h2 style='text-align:center'> Analysis results of "+apkfile+" </h2> </u>")	
	os.system('jadx -d ./ "' +apkfile+'"')
	# os.system('java -jar apktool.jar d -q "' + apkfile +'"')
	writeResults(filename,"</br> <u><h2 style='text-align:center; color:red'>Failed Test Cases</h2></u> </br> </br> <hr  style='border: none; background: black; height: 12px;margin-bottom: 50px'>")
	isDebuggableOrBackup()
	network_security_config_Test(filename, nscFile)
	fireBaseTest(filename, stringsFile)
	getDeepLinks()
	try:
		f11=open(resultsHtmlTemp, "r")
		writeResults(filename, "</br>  <u> <h2 style='text-align:center; color:green'>Passed Test Cases</h2> </u> </br> </br> <hr style='border: none; background: black; height: 12px;margin-bottom: 50px'>"+f11.read())
		writeResults(filename,"<hr style='border: none; background: black; height: 12px;margin-bottom: 50px'>")
		writeResults(filename,"<div style='text-align:center; padding-top:10px; padding-bottom:10px; height:20px'> @copyright2022 by siddharth </div>"+endhtml)
		f11.close()
		os.remove(resultsHtmlTemp)
	except IOError:
		writeResults(filename,endhtml)
	print("Results are printed in "+pwd+"\\"+resultsHtml)
# if file extension is not .apk
else:
	writeResults(filename,"</br>Please use apk file only")