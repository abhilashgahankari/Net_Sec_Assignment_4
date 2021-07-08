Q3.py
#input from pcap file
#wrties table SessionLen on terminal
#writes the data in SessionLen table in NS.db
from scapy.all import *
from tabulate import tabulate
from itertools import groupby
import sqlite3

#initialize
ips = {}
tuples = []
a_time = []

data_file = '5mb_file.pcap' #filename of input file
pcap = rdpcap(data_file)

def build_dict(pkt):
    port_count = 1

    if pkt.haslayer(IP):
        s_ip = pkt[IP].src
        d_ip = pkt[IP].dst
        if pkt.haslayer(UDP) or pkt.haslayer(TCP):
            s_port = pkt.sport
            d_port = pkt.dport
            tuples.append([s_ip,d_ip,s_port,d_port,pkt.time])


ip_pair = []
ip_pair2 = []

l1 =[]
l2 =[]

for pkt in pcap:
    time = pkt.time
    build_dict(pkt)

tuples.sort()

for key, group in groupby(tuples, key=lambda x: x[:4]):
    x = (max(i for i in group))
    l1.append(x)
    
for key, group in groupby(tuples, key=lambda x: x[:4]):
    y = (min(i for i in group))
    l2.append(y)
    
Output = []
  
for i in range(len(l1)):
    l1[i][4] = l1[i][4] - l2[i][4]
        
print(tabulate(l1, headers=['Source', 'Destination','Sport','Dport','Time'], tablefmt='orgtbl'))


#Connecting to sqlite
conn = sqlite3.connect('NS.db')
cursor = conn.cursor()
cursor.execute("DROP TABLE IF EXISTS SessionLen")

#Creating table as per requirement
sql ='''CREATE TABLE SessionLen(
   IP1 TEXT NOT NULL,
   IP2 TEXT NOT NULL,
   Port1 TEXT,
   Port2 TEXT,
   SessionLen FLOAT
)'''
cursor.execute(sql)
print("Table created successfully........")

for i in range(len(l1)):
    s = "INSERT INTO SessionLen(IP1, IP2, Port1,Port2, SessionLen) VALUES('" + str(l1[i][0]) +"','"+ str(l1[i][1]) + "','"+ str(l1[i][2])+"','"+str(l1[i][3])+"',"+ str(l1[i][4])+")"
    # print(s)
    cursor.execute(s)
conn.commit()
print("Written to Table successfully........")

#Closing the connection
conn.close()