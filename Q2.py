#input from pcap file
#wrties table IPPairStat on terminal
#writes the data in IPPairStat table in NS.db
from scapy.all import *
from tabulate import tabulate
from itertools import groupby
import sqlite3

#reading the file
def readfile(filename):
    pkts = rdpcap(filename)
    return pkts

#get unique ips from pkts
def get_unique_ips(pkts):
    ip_pair_list = []
    for pkt in pkts:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ip_pair = [src_ip, dst_ip]
            rev_pair = [dst_ip, src_ip]
            if rev_pair not in ip_pair_list:
                ip_pair_list.append(ip_pair)
    return ip_pair_list

#get num of pkts and size of pkts for each unique ip
def get_num_pkts_and_size_for_ip(ip, pkts):
    numpkts = 0
    sizeforip = 0
    for pkt in pkts:
        if IP in pkt:
            if ip == pkt[IP].src or ip == pkt[IP].dst:
                numpkts += 1
                sizeforip += len(pkt)
    return numpkts, sizeforip

def remove_list_duplicates(ip_pair_list):
    ip_pair_list.sort()
    ip_pairs_unique = list(ip_pair_list for ip_pair_list,_ in groupby(ip_pair_list))
    return ip_pairs_unique

if __name__ == '__main__':
    data_file = '../smartbulb (1).pcap' #filename for input pcap file
    pkts = readfile(data_file)
    ip_pair_list = get_unique_ips(pkts)
    ip_pairs_unique = remove_list_duplicates(ip_pair_list)

    npkts = []
    nbytes = []
    nports = []
    for ip in ip_pairs_unique:
        ip1 = ip[0]
        ip2 = ip[1]
        ports = []
        pktcnt = 0
        bytecnt = 0
        for pkt in pkts:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                if(src_ip == ip1 and dst_ip == ip2) or (src_ip == ip2 and dst_ip == ip1):
                    pktcnt += 1
                    bytecnt += len(pkt)
                    if pkt.haslayer('TCP') or pkt.haslayer('UDP'):
                        srcport = pkt.sport
                        dstport = pkt.dport
                        if pkt.haslayer('TCP') or pkt.haslayer('UDP'):
                            if (srcport not in ports and  dstport not in ports):
                                ports.append(srcport)
                                ports.append(dstport)
        npkts.append(pktcnt)
        nbytes.append(bytecnt)
        nports.append(len(ports))
    
    output = []
    
    for i in range(len(ip_pairs_unique)):
        ip_pair = ip_pairs_unique[i]
        ip1 = ip_pair[0]
        ip2 = ip_pair[1]
        output.append([ip1, ip2, npkts[i], nbytes[i], nports[i]])
        
    print(tabulate(output, headers=['IP1','IP2','npkts', 'nbytes', 'nports'],  tablefmt='orgtbl'))


#Connecting to sqlite
conn = sqlite3.connect('NS.db')
cursor = conn.cursor()
cursor.execute("DROP TABLE IF EXISTS IPPairStat")

#Creating table as per requirement
sql ='''CREATE TABLE IPPairStat(
   IP1 TEXT NOT NULL,
   IP2 TEXT NOT NULL,
   nPKts INT,
   nBytes INT,
   nPorts INT
)'''
cursor.execute(sql)
print("Table created successfully........")

for i in range(len(output)):
    s = "INSERT INTO IPPairStat(IP1, IP2, nPKts, nBytes, nPorts) VALUES('" + str(output[i][0]) +"','"+ str(output[i][1]) +"',"+ str(output[i][2])+","+str(output[i][3])+","+ str(output[i][4])+")"
    # print(s)
    cursor.execute(s)
conn.commit()
print("Written to Table successfully........")

#Closing the connection
conn.close()