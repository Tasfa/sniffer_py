#! /usr/bin/python
################################################
#
# Author:Tasfa
# Date:2016/03
# Platform:Kali-linux-2.0-Rolling
# Dsc:My own sniffer using scapy to capture
#     data packets and try to analyse them.
#
################################################


import os
import sys
import getopt
import pyx
from scapy.all import *

####################Global Var####################
global summary_flag


#####################The usage of this sniffer#############
def Usage():
    print "Sniffer's usage:"
    print '  -h,--help:print this help message'
    print '  -i,--iface:Enter your interface'
    print '  -f,--filter:Input your filter'
    print "  -c,--count:The Packets' numbers you want to catch"
    print '  -w,--write:Write your data into a pcap file'
    print '  -r,--read:Read your own pcap file'
    print '  -W,Read the pcap file by using the wireshark'
    print '  -s:print the summary of capturing packets '
    print '  -v,--version:Print script version'
    print ""
    print 'EXAMPLES:'
    print '  sniffer -i eth0 -c 30 -d'
    print '  sniffer -r tasfa.pcap'
    print '  Welcome to my blog for more infomation(www.tasfa.cn)'

#####################The version of the Sniffer##################
def Version():
    print '  Sniffer 1.0--Python 2.7'

def packet_callback(packet):  
    print packet.show() 

#####################The funtion of capture packets################
def Sniff(iface1='eth0',filter1='',count1='3',summary_flag=False):
    global pkts
   
    if(summary_flag):
        pkts=sniff(iface='eth0',filter=filter1,count=count1,prn=lambda x: x.summary())
        pkts.pdfdump(layer_shift=1)
    else:
        pkts=sniff(iface='eth0',filter=filter1,count=count1,prn=packet_callback)
    
#####################Write the packets into a pcap file####################
def Write2pcap(filename_w):
    try:
        wrpcap("test.cap",pkts)
    except:
	print '\033[1;31;40m'
	print '*'*60
	print 'Attention Please'
        print 'Please check your input'
	print '*'*60
	print '\033[0m'
        Usage()	
        sys.exit(2)    

#####################Read a pcap file###################
def Readpcap(filename_r,id_wshark):
    if id_wshark==0:
        read_pkts = rdpcap(filename_r)
        read_pkts.show()
    else:
        os.system('wireshark '+filename_r)

#####################The main function###################
def main():
    iface1=""
    filter1=""
    count1=1
    sniff_flag=True
    summary_flag=False	
    try:
        opts,args=getopt.getopt(sys.argv[1:],'hi:f:c:w:r:dvW:',["help", "iface=", "filter=","count=","write=","read=","version"])
    except getopt.GetoptError,err:
        print str(err)
        Usage()
        sys.exit(2)  
    for o,a in opts:
        if o in ('-h','--help'):
	    sniff_flag=False
            Usage()       
        elif o in ('-i','--iface'):
            iface1=a	    
	elif o in ('-f','--filter'):
	    filter1=a           
	elif o in ('-c','--count'):
            count1=int(a)	    
	elif o in ('-w','--write'):
	    sniff_flag=False
	    filename_w=a
            Write2pcap(filename_w)        
	elif o in ('-r','--read','-W'):
	    filename_r=a
	    sniff_flag=False	   
	    if o == '-W':
                id_wshark=1
	    else:
		id_wshark=0	    
	    try:
                Readpcap(filename_r,id_wshark)
            except:
		print '\033[1;31;40m'
		print '*'*60
		print 'Attention Please!'
       		print 'Please check your Filepath and the Filename again'
		print '*'*60
		print '\033[0m'
	        Usage()
	elif o in ('-v','--version'):
	    sniff_flag=False
            Version()
	elif o in ('-d'):
            summary_flag=True
	else:
	    Usage()
    if sniff_flag == True:
        Sniff(iface1,filter1,count1,summary_flag)
	
        

if __name__ == '__main__':
    main()
