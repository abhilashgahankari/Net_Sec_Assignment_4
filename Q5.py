#input from pcap file
#wrties table TupleRTT on terminal
#writes the data in TupleRTT table in NS.db

from scapy.all import *
from ipaddress import ip_address
from tabulate import tabulate
import decimal
import sqlite3


res_rtt = []

def process_this_pkt_group(pkts_list):
    global pkt_num
    pkt_count = 0 
    for i in range(len(pkts_list)):
        if pkts_list[i].haslayer(IP):
            pkt_count +=1
    
    # print(pkt_count)
    # print('processing packets group: pkt count = ', len(pkts_list))
    
    if(pkt_count <= 1):
        return
    
    rtt = list()
    i = 0
    j = 1
    
    while(i < pkt_count and j < pkt_count ):

        if pkts_list[i].haslayer(IP) and (pkts_list[i].haslayer('TCP') or pkts_list[i].haslayer('UDP')):
            s_ip = pkts_list[i][IP].src
            d_ip = pkts_list[i][IP].dst
            s_port = pkts_list[i].sport
            d_port = pkts_list[i].dport
            time1 = pkts_list[i].time

            s_ip2 = pkts_list[j][IP].src
            d_ip2 = pkts_list[j][IP].dst
            s_port2 = pkts_list[j].sport
            d_port2 = pkts_list[j].dport
            time2 = pkts_list[j].time
            
            tup1 = s_ip+d_ip+str(s_port)+str(d_port)
            tup2 = d_ip2+s_ip2+str(d_port2)+str(s_port2)
            tup3 = s_ip2+d_ip2+str(s_port2)+str(d_port2)
                        
            if(tup1 == tup2):
                time_d = time2 - time1
                res_rtt.append([s_ip,d_ip,s_port,d_port,time_d])
                res_rtt.append([d_ip,s_ip,d_port,s_port,time_d])
                i+=2
                j+=2
              
            if(tup1 == tup3):
                time_d = time2 - time1
                res_rtt.append([s_ip,d_ip,s_port,d_port,0])
                i+=1
                j+=1

            if(j==pkt_count):
                res_rtt.append([s_ip,d_ip,s_port,d_port,0]) 

def process_this_pkt_group_single(pkts_list):
    global pkt_num
    # print('processing packets group: pkt count = ', len(pkts_list))
    pkt_count = len(pkts_list)
    time = list()
    if pkt_count == 1:
        return
    for i in range(pkt_count):
        time.append(pkts_list[i].time)
    result = [b-a for a, b in zip(time[:-1], time[1:])]
    time_gap = list()
    time_gap.append(result)
    
    for i in range(pkt_count):
        if pkts_list[i].haslayer(IP):
            s_ip = pkts_list[i][IP].src
            d_ip = pkts_list[i][IP].dst
            # print(s_ip,d_ip)
    # print('time_gap',time_gap)


def full_duplex(p):
    sess = "Other"
    if 'Ether' in p:
        if 'IP' in p:
            if 'TCP' in p:
                sess = str(sorted(["TCP", p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport],key=str))
            elif 'UDP' in p:
                sess = str(sorted(["UDP", p[IP].src, p[UDP].sport, p[IP].dst, p[UDP].dport] ,key=str))
            elif 'ICMP' in p:
                sess = str(sorted(["ICMP", p[IP].src, p[IP].dst, p[ICMP].code, p[ICMP].type, p[ICMP].id] ,key=str)) 
            else:
                sess = str(sorted(["IP", p[IP].src, p[IP].dst, p[IP].proto] ,key=str)) 
        elif 'ARP' in p:
            sess = str(sorted(["ARP", p[ARP].psrc, p[ARP].pdst],key=str)) 
        else:
            sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
    return sess

if __name__=='__main__':
    file_name = 'tcpdump.pcap'
    pkt = rdpcap(file_name)
    pkts = sniff(offline = file_name)
    sess = pkts.sessions()
    full = pkts.sessions(full_duplex)
    for s in full:
        process_this_pkt_group(full[s])

print(tabulate(res_rtt, headers=['IP1', 'IP2','Port1','Port2','time_diff'], tablefmt='orgtbl'))

#Connecting to sqlite
conn = sqlite3.connect('NS.db')
cursor = conn.cursor()
cursor.execute("DROP TABLE IF EXISTS TupleRTT")

#Creating table as per requirement
sql ='''CREATE TABLE TupleRTT(
   IP1 TEXT NOT NULL,
   IP2 TEXT NOT NULL,
   Port1 INT,
   Port2 INT,
   time_diff FLOAT
)'''
cursor.execute(sql)
print("Table created successfully........")

for i in range(len(res_rtt)):
    s = "INSERT INTO TupleRTT(IP1, IP2, Port1,Port2, time_diff) VALUES('" + str(res_rtt[i][0]) +"','"+ str(res_rtt[i][1]) + "',"+ str(res_rtt[i][2])+","+str(res_rtt[i][3])+","+ str(res_rtt[i][4]) + ")"
    # print(s)
    cursor.execute(s)
conn.commit()
print("Written to Table successfully........")

#Closing the connection
conn.close()
