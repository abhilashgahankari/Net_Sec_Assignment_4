#reads from pcap file
#writes the table on the terminal 
#writes the table IPStat in the NS.db database
from scapy.all import *
from tabulate import tabulate
import sqlite3

#function to read the file
def readfile(filename):
    #reading the file
    pkts = rdpcap(filename)
    return pkts

#to get unique ips form pkts
def get_unique_ips(pkts):
    unique_ips = list()
    for pkt in pkts:
        if IP in pkt:
            if pkt[IP].src not in unique_ips:
                unique_ips.append(pkt[IP].src)
            if pkt[IP].dst not in unique_ips:
                unique_ips.append(pkt[IP].dst)
    # print('Done get_unique_ips')
    return unique_ips

#to calculate the pkt sizes and number of pkts for each unique ip
def get_num_pkts_and_size_for_ip(ip, pkts):
    numpkts = 0
    sizeforip = 0
    for pkt in pkts:
        if IP in pkt:
            if ip == pkt[IP].src or ip == pkt[IP].dst:
                numpkts += 1
                sizeforip += len(pkt)
    #print('Done get_unique_ips')
    return numpkts, sizeforip

#to check whether ip is public or private
def is_public_ip(ip):
    ip = list(map(int, ip.strip().split('.')[:2]))
    if ip[0] == 10: return False
    if ip[0] == 172 and ip[1] in range(16, 32): return False
    if ip[0] == 192 and ip[1] == 168: return False
    return True

if __name__ == '__main__':
    # testdata_filename = 'smartbulb (1).pcap'
    data_file = '../smartbulb (1).pcap' #filename of pcap input file
    pkts = readfile(data_file)
    unique_ips_src_dst = get_unique_ips(pkts)
    
    numpkts_for_ips = list()
    size_for_ip = list()
    for ip in unique_ips_src_dst:
        numpkts, sizeforip = get_num_pkts_and_size_for_ip(ip,pkts)
        numpkts_for_ips.append(numpkts)
        size_for_ip.append(sizeforip)
    
    #output list
    tbl = list()
    
    for i in range(len(unique_ips_src_dst)):
        tbl.append([unique_ips_src_dst[i], 'Public' if is_public_ip(unique_ips_src_dst[i]) else 'Private',numpkts_for_ips[i], size_for_ip[i]])
    print(tabulate(tbl, headers=['IP','isPublic', 'nPkt', 'nBytes'],  tablefmt='orgtbl'))
    
        
    #Connecting to sqlite
    conn = sqlite3.connect('NS.db')
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS IPStat")

    #Creating table as per requirement
    sql ='''CREATE TABLE IPStat(
    IP TEXT NOT NULL,
    isPublic TEXT,
    nPkts INT,
    nBytes INT
    )'''
    cursor.execute(sql)
    print("Table created successfully........")

    for i in range(len(tbl)):
        s = "INSERT INTO IPStat(IP, isPublic,nPkts, nBytes) VALUES('" + str(tbl[i][0]) +"','"+ str(tbl[i][1])+"',"+str(tbl[i][2])+","+ str(tbl[i][3])+")"
        # print(s)
        cursor.execute(s)
    conn.commit()
    print("Written to Table successfully........")
    #Closing the connection
    conn.close()