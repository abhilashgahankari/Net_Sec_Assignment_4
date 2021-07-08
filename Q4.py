#input from pcap file
#wrties table TupleStat on terminal
#writes the data in TupleStat table in NS.db

from scapy.all import *
from tabulate import tabulate
from itertools import groupby
import sqlite3

ips = {}

tuples = []
a_time = []

data_file = '../smartbulb (1).pcap' #filenanme of input pcap file
pcap = rdpcap(data_file)

def build_dict(pkt):
    port_count = 1

    if pkt.haslayer(IP):
        s_ip = pkt[IP].src
        d_ip = pkt[IP].dst
        if pkt.haslayer(UDP) or pkt.haslayer(TCP):
            s_port = pkt.sport
            d_port = pkt.dport
            tuples.append([s_ip,d_ip,s_port,d_port])
            
ip_pair = []
ip_pair2 = []

for pkt in pcap:
    time = pkt.time
    build_dict(pkt)

tuples.sort()

l1 =[]
l2 =[]
for key, group in groupby(tuples, key=lambda x: x[:4]):
    x = (max(i for i in group))
    l1.append(x)
    
for key, group in groupby(tuples, key=lambda x: x[:4]):
    y = (min(i for i in group))
    l2.append(y)
    
Output = []
nbytes = []
npkts = []

for i in l1:
    sourc_ip = i[0]
    dest_ip = i[1]
    sport = i[2]
    dport = i[3]
    length = 0
    pktlen = 0
    for pkt in pcap:
        if IP in pkt:
            if pkt.haslayer('TCP') or pkt.haslayer('UDP'):
                if pkt[IP].src == sourc_ip and pkt.sport == sport:
                    if pkt.haslayer('TCP') or pkt.haslayer('UDP'):
                        if pkt[IP].dst == dest_ip and pkt.dport == dport:
                            length += len(pkt)
                            pktlen += 1
    nbytes.append(length)
    npkts.append(pktlen)

# print(len(npkts))
for i in range(len(l1)):
    l1[i].append(nbytes[i])
    l1[i].append(npkts[i])

for i in l1:
    row = []
    sourc_ip = i[0]
    dest_ip = i[1]
    sport = i[2]
    dport = i[3]
    lens = i[4]
    pkts = i[5]
    final_len = lens
    final_pkts = pkts
    len2 = 0
    pkt2 = 0
    i = 0
    for j in l1:
        if j[0] == dest_ip and j[1] == sourc_ip and j[2] == dport and j[3] == sport:
            len2 = j[4]
            pkt2 = j[5]
            final_len += j[4]
            final_pkts += j[5]
            l1.pop(i)
        i += 1
    Output.append([sourc_ip,dest_ip,sport,dport,lens,pkts,len2,pkt2, final_len, final_pkts])
    

print(tabulate(Output, headers=['IP1', 'IP2','Port1','Port2', 'nBytesfromIP1','npktsfromIP1',  'nBytesfromIP2', 'npktsfromIP2', 'nbytestotal', 'npkttotal'], tablefmt='orgtbl'))

#Connecting to sqlite
conn = sqlite3.connect('NS.db')
cursor = conn.cursor()
cursor.execute("DROP TABLE IF EXISTS TupleStat")

#Creating table as per requirement
sql ='''CREATE TABLE TupleStat(
   IP1 TEXT NOT NULL,
   IP2 TEXT NOT NULL,
   Port1 INT,
   Port2 INT,
   nPktsFromIP1 INT,
   nBytesFromIP1 FLOAT,
   nPktsFromIP2 INT,
   nBytesFromIP2 FLOAT,
   nPktTotal INT,
   nBytesTotal FLOAT
)'''
cursor.execute(sql)
print("Table created successfully........")

for i in range(len(Output)):
    s = "INSERT INTO TupleStat(IP1, IP2, Port1,Port2, nPktsFromIP1,nBytesFromIP1,nPktsFromIP2,nBytesFromIP2,nPktTotal,nBytesTotal) VALUES('" + str(Output[i][0]) +"','"+ str(Output[i][1]) + "',"+ str(Output[i][2])+","+str(Output[i][3])+","+ str(Output[i][4])+"," + str(Output[i][5]) + "," + str(Output[i][6]) + ","+ str(Output[i][7]) + ","+ str(Output[i][8]) + "," + str(Output[i][9]) + ")"
    # print(s)
    cursor.execute(s)
conn.commit()
print("Written to Table successfully........")

#Closing the connection
conn.close()