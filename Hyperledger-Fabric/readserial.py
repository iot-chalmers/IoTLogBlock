
import sys,socket
import threading
import serial
import time
import numpy as np
import sys
# from ecdsa import VerifyingKey
from Naked.toolshed.shell import muterun_js

update_avg = threading.Lock()
log_name = 'gen3000s-edge1s.txt'
drop_records = 0
total_memory = 42
# ser = '/dev/tty.usbserial-00002501B'
ser = sys.argv[1]
print (ser)
timestamps={}
tranx_count = 1
buffer = ""
counter = 0

base_time = time.time() 

avag_time = []
avg_mem_usage = []
avg_drop_rate = []

def serial_data(port, baudrate):
    ser = serial.Serial(port, baudrate)
    while True:
        yield ser.readline()

    ser.close()

signature = False

def request_to_ledger(iot_record):
    rec_id = int(iot_record[0])
    # print timestamps.keys()
    # print rec_id
    # print rec_id in timestamps.keys()
    # if rec_id in timestamps.keys():
        # delay1 = time.time() -  timestamps[rec_id]
        # print "timestamp "
        # print timestamps[rec_id]
        # print "delay 1 : "
        # print delay1 
    response = muterun_js('invoke.js',"{} {} {} {} {} {} {} {}".format(*iot_record))
    if response.exitcode == 0:
        # print "blockchain not connected"
        print(response.stdout)
        if rec_id in timestamps.keys():
            update_avg.acquire()
            delay2 = time.time() -  timestamps[rec_id]
            print ("new delay : ", delay2)
            avag_time.append(delay2)
            new_avg_mean = np.mean(avag_time)
            new_avg_std  =  np.std(avag_time)
            print ("avg delay time : ", np.mean(avag_time) )
            print ("std on delay time : " , np.std(avag_time) )
            f = open(log_name,"a+")
            f.write("DELAY mean:%f std:%f \n"%(new_avg_mean,new_avg_std))
            f.close()
            update_avg.release()
           
    else:
        sys.stderr.write(response.stderr)


def sendSign(line):

	#args: ['Device'.concat(sender),'Device'.concat(rcver),'Tx'.concat(Transx),signature,cargo_id],
    # global tranx_count
    # tranx_count += 1
    # line = line.strip('\n')
    args = line.split('\n')
    thread = threading.Thread(target=request_to_ledger, args=(args, ) )
    thread.daemon = True
    thread.start()

def write_to_file(new_line):
    f= open(log_name,"a+")
    f.write(new_line)
    f.close()     

for line in serial_data(ser, 115200):
    if line == '</transcation>\n' :
        signature = False
        sendSign (buffer)
        buffer = ""
    if signature :
        buffer = buffer + line
    if line == '<transcation>\n' :
        signature = True
    if '<rec_timestamp>' in line:
        record_id = line.replace('<rec_timestamp>','').replace('\n','')
        print ("Transcation in total: ", record_id )
        # interval = base_time - tome()
        diff = int(time.time() - base_time)
        newline = "Records in total:%s , timestamp: %d \n"%(record_id,diff)
        write_to_file (newline)
        tranx_count += 1
        # f.write("Transcation requests in total:%d\n"%tranx_count)
        timestamps[int(record_id)] = time.time()
        # print timestamps
    if '<buffer_counter>' in line:
        buffer_size = line.replace('<buffer_counter>','').replace('\n','')
        print ("buffer size: ", buffer_size )
        mem_use_instrance = float(buffer_size)/ total_memory
        print ("total memory ussage: ", mem_use_instrance )
        avg_mem_usage.append(mem_use_instrance)
        avg_mean_mem = np.mean(avg_mem_usage)
        avg_std_mem = np.std(avg_mem_usage)
        print ("avg mem use   : ", avg_mean_mem)
        print ("std on mem use: " , avg_std_mem)
        newline ="avg mem use:%f std:%f \n"%(avg_mean_mem,avg_std_mem)
        write_to_file(newline)
    if '<drop_record>' in line:
        drop_records += 1
        print ("dropped rec: ", drop_records)
        drop_rate_instannce = float(drop_records) / tranx_count
        print ("drop_rate ",drop_rate_instannce)
        avg_drop_rate.append(drop_rate_instannce)
        avg_mean_drop_rate = np.mean(avg_drop_rate)
        avg_std_drop_rate  = np.std(avg_drop_rate)
        print ("avg drop_rate   : ", avg_mean_drop_rate)
        print ("std on drop_rate: " , avg_std_drop_rate)
        newline = "avg drop_rate:%f std:%f \n"%(avg_mean_drop_rate,avg_std_drop_rate)
        write_to_file(newline)
    if '<record_request>' in line:
        # f= open(log_name,"a+")
        tranx_count += 1
        newline = "Transcation requests in total:%d\n"%tranx_count
        write_to_file (newline)
    if 'Energest:' in line:
        write_to_file(line)
    
    #mySubString=line[line.find("signature")+1:line.find("/signature")]
    #print mySubString