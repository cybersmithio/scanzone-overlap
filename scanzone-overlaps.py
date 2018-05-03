#!/usr/bin/python
# Written by: James Smith
# Version: 0.9 
# Created: June 13, 2017
#
# This is a concept script meant to see if any scan zones in SecurityCenter have an overlap.
#
# Set these environment variables to log in:
#     SCHOST
#     SCUSERNAME
#     SCPASSWORD
#
#
# Requires the following:
#   pip install pysecuritycenter
#   pip install ipaddr
#   pip install netaddr

from securitycenter import SecurityCenter5
import ipaddr
import json
import netaddr
import string
import os

###############################################
# CODE BELOW HERE - NOTHING TO CHANGE BY USER #
###############################################

def checkScanZones(sc):
	print("Beginning check of scan zones")
	#Download all the scanzone names
	resp=sc.get('zone?fields=name%2Cscanners%2CtotalScanners%2CactiveScanners%2CtotalScanners%2CmodifiedTime%2CcanUse%2CcanManage')

	#create an empty list of scan zone ranges
	scanzoneranges=[]

	#Iterate through all the scan zones and download the IP ranges
	for i in resp.json()['response']:
		print "Examining scan zone \""+i['name']+"\""
		#print "id",i['id']
		resp=sc.get('zone/'+str(i['id'])+'?fields=name%2Cdescription%2CipList%2CcreatedTime%2Cranges%2Cscanners%2Cname%2Cscanners%2CtotalScanners%2CactiveScanners%2CtotalScanners%2CmodifiedTime%2CcanUse%2CcanManage')
		iplist=resp.json()['response']['ipList'].split(',')
		for j in iplist:
			#print "IP Range in scan zone",j

			#Check if the IP address is an IP range (instead of a single IP or CIDR)
			hyphen=string.find(j,"-")
			if( hyphen >= 0 ):
				#If the IP address is a range, convert it to CIDR notation
				#print "CIDRs",netaddr.iprange_to_cidrs(j[0:hyphen],j[hyphen+1:])
				for k in netaddr.iprange_to_cidrs(j[0:hyphen],j[hyphen+1:]):
					scanzoneranges.append([k,i])
			else:
				scanzoneranges.append([j,i])


	#Examine all the network ranges for overlaps
	#Go through all the ranges, comparing each one to all the other ranges,
	for i in range(0,len(scanzoneranges)):
		n1=ipaddr.IPNetwork(scanzoneranges[i][0])

		for j in range(i+1,len(scanzoneranges)):
			n2=ipaddr.IPNetwork(scanzoneranges[j][0])
			if n1.overlaps(n2):
				print n1,"in scan zone \""+str(scanzoneranges[i][1]['name'])+"\" overlaps with",n2,"in scan zone \""+str(scanzoneranges[j][1]['name'])+"\""

	return(True)





######################
###
### Program start
###
######################
# Look for SecurityCenter login information
if os.getenv('SCHOST') is None:
	schost = ""
else:
	schost = os.getenv('SCHOST')

if os.getenv('SCUSERNAME') is None:
	username = ""
else:
	username = os.getenv('SCUSERNAME')

if os.getenv('SCPASSWORD') is None:
	password = ""
else:
	password = os.getenv('SCPASSWORD')

# Create a session as the user
try:
	scconn = SecurityCenter5(schost)
except:
	print "Unable to connect to SecurityCenter"
	print("Make sure to set SCHOST, SCUSERNAME, and SCPASSWORD environment variables and export them.")
	exit(-1)

try:
	scconn.login(username, password)
except:
	print "Unable to log into SecurityCenter"
	print("Make sure to set SCHOST, SCUSERNAME, and SCPASSWORD environment variables and export them.")

print("Logged into SecurityCenter")
checkScanZones(scconn)

exit()