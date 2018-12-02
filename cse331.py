import re
import time
from time import strftime
import subprocess
import json
import datetime



##########READ PREPROCESSES FILE############
class Client:
    def __init__(self, ip_address, first_login, fail_requests, time_blocked, remove_blacklist, last_time_incr):
        self.ip_address = ip_address
        self.first_login = first_login
        self.fail_requests = int(fail_requests)
        self.time_blocked = time_blocked
        self.remove_blacklist = remove_blacklist
	self.last_time_incr = last_time_incr

with open("/home/ubuntu/Documents/cse331/myapp/clientdata.json") as data_json_file:
    data = json.load(data_json_file)
    admindata = data['admindata']
    request = int(admindata['requestlimit'])
    request_window = int(admindata['requestwindow'])
    block_dur = int(admindata['blockduration'])
    clientdata = data['clientdata']
    clients = clientdata['clients']
    client_list = []
    for c in clients:
        clientIP = c['ipaddress']
        client_first_login = c['firstlogin']
        client_failed_requests = c['failedrequests']
        client_time_blocked = c['timeblocked']
        client_remove_blacklist = c['removeblacklist']
	client_last_time_incr = c['lasttimeincr']
        client = Client(clientIP, client_first_login, client_failed_requests, client_time_blocked, client_remove_blacklist, client_last_time_incr)
        client_list.append(client)


def block_ip(ip):
    cmd="sudo iptables -I INPUT -s "+ip+" -j DROP"
    print cmd
    subprocess.call(cmd.split())

def unblock_ip(ip):
    cmd="sudo iptables -D INPUT -s "+ip+" -j DROP"
    print cmd
    subprocess.call(cmd.split())



def checkMonth(Mon):
    if Mon == 'Jan':
        return '1'
    elif Mon == 'Feb':
        return '2'
    elif Mon == 'Mar':
        return '3'
    elif Mon == 'Apr':
        return '4'
    elif Mon == 'May':
        return '5'
    elif Mon == 'Jun':
        return '6'
    elif Mon == 'Jul':
        return '7'
    elif Mon == 'Aug':
        return '8'
    elif Mon == 'Sep':
        return '9'
    elif Mon == 'Oct':
        return '10'
    elif Mon == 'Nov':
        return '11'
    elif Mon == 'Dec':
        return '12'



def convertTime(time):
    #time = input('Please enter a time: ')

    timeArr = time.split(":")
    #print(timeArr)
    hour = timeArr[1]
    minute = timeArr[2]
    second = timeArr[3]

    y = timeArr[0].split("/")

    #print(y)

    year = y[2]
    month = checkMonth(y[1])
    day = y[0]

    date = year + "-" + month + "-" + day + " " + hour + ":" + minute + ":" + second
    return  date
    #print(date)

def SSH_datetime(input):
    timeList=re.split(' ',input,1)
    month='12'
    if timeList[0]=='Jan':
        month='1'
    elif timeList[0] == 'Feb':
        month = '2'
    elif timeList[0] == 'Mar':
        month = '3'
    elif timeList[0] == 'Apr':
        month = '4'
    elif timeList[0] == 'May':
        month = '5'
    elif timeList[0] == 'Jun':
        month = '6'
    elif timeList[0] == 'Jul':
        month = '7'
    elif timeList[0] == 'Aug':
        month = '8'
    elif timeList[0] == 'Sep':
        month = '9'
    elif timeList[0] == 'Oct':
        month = '10'
    elif timeList[0] == 'Nov':
        month = '11'
    timeList[1] = timeList[1].strip()
    result='2018-'+month+'-'+timeList[1]
    return result

   
        

###########READ FILE############
log_file_path = r"/var/log/apache2/access.log" #webserver log
ssh_log_file =  r"/var/log/auth.log" #SSH LOG

dict_check = {}




parse_IP = '(\d+\.\d+\.\d+\.\d+)'
parse_WP = '(\"POST\s.+200)'
parse_php = '(mysql-denied)'
parse_jm = '(GET \/index\.php\/component\/users\/\?view=login&Itemid=101)'
parse_ssh = '(Invalid)'

parse_time = '(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2})'
parse_ssh_time = '(\w{3}\s{1,3}\d{1,2}\s{1,3}\d{2}:\d{2}:\d{2})'


def parseApacheData(log_file_path, parse_WP, parse_jm, parse_php, parse_IP):
    #match_list = []
    notin_flag = False
    tail = subprocess.Popen(('tail', '--lines=25', log_file_path), stdout=subprocess.PIPE)
    for line in tail.stdout:
	#print line
        for match in re.finditer(parse_WP, line, re.S):
            match_text = match.group()
                # match_list.append(match_text)
            search_IP = re.search(parse_IP, line, re.S)
            match_IP = search_IP.group()
                ##### PARSE THE TIME######
            search_time = re.search(parse_time, line, re.S)
            time_tried = search_time.group()
            time_tried = convertTime(time_tried)
                ##### CHECK THE IP ADDRESS IN THE client_list IF IT EXISTS ######
            for client in client_list:
                if client.ip_address == match_IP and time_tried != client.last_time_incr:
                    client.fail_requests = client.fail_requests + 1
                    client.last_time_incr = time_tried
                    notin_flag = True
            if notin_flag == False:
                newclient = Client(match_IP, time_tried, 1, None, False, time_tried)
                client_list.append(newclient)
            notin_flag = False

                ##### IF THE NUMBERS OF REQUESTED IS OVER THE LIMITE #####
                ##### CALL BLCOK IP METHOD #####
            for client in client_list:
                if client.fail_requests >= request and (client.time_blocked is None or client.time_blocked == 'null'):
                    client.time_blocked = str(datetime.datetime.now() + datetime.timedelta(minutes=block_dur))
                    splite_last_dec = client.time_blocked.rpartition('.')
                    client.time_blocked = splite_last_dec[0]
		    block_ip(client.ip_address)
                # ip_dict(match_IP)

        for match in re.finditer(parse_jm, line, re.S):
            match_text = match.group()
                 #match_list.append(match_text)
            search_IP = re.search(parse_IP, line, re.S)
            match_IP = search_IP.group()
                ##### PARSE THE TIME######
            search_time = re.search(parse_time, line, re.S)
            time_tried = search_time.group()
            time_tried = convertTime(time_tried)
                ##### CHECK THE IP ADDRESS IN THE client_list IF IT EXISTS ######
            for client in client_list:
                if client.ip_address == match_IP and time_tried != client.last_time_incr:
                    client.fail_requests = client.fail_requests + 1
                    client.last_time_incr = time_tried
		    notin_flag = True
            if notin_flag == False:
                newclient = Client(match_IP, time_tried, 1, None, False, time_tried)
                client_list.append(newclient)
            notin_flag = False

                    ##### IF THE NUMBERS OF REQUESTED IS OVER THE LIMITE #####
                    ##### CALL BLCOK IP METHOD #####
            for client in client_list:
                if client.fail_requests >= request and (client.time_blocked is None or client.time_blocked == 'null'):
                    client.time_blocked = str(datetime.datetime.now() + datetime.timedelta(minutes=block_dur))
                    splite_last_dec = client.time_blocked.rpartition('.')
                    client.time_blocked = splite_last_dec[0]
                    block_ip(client.ip_address)

        for match in re.finditer(parse_php, line, re.S):
            match_text = match.group()
                #match_list.append(match_text)
            search_IP = re.search(parse_IP, line, re.S)
            match_IP = search_IP.group()
                ##### PARSE THE TIME######
            search_time = re.search(parse_time, line, re.S)
            time_tried = search_time.group()
            time_tried = convertTime(time_tried)
                ##### CHECK THE IP ADDRESS IN THE client_list IF IT EXISTS ######
            for client in client_list:
                if client.ip_address == match_IP and client.last_time_incr != time_tried:
                    client.fail_requests = client.fail_requests + 1
		    client.last_time_incr = time_tried
                    notin_flag = True
            if notin_flag == False:
                newclient = Client(match_IP, time_tried, 1, None, False, time_tried)
                client_list.append(newclient)
            notin_flag = False

                    ##### IF THE NUMBERS OF REQUESTED IS OVER THE LIMITE #####
                    ##### CALL BLCOK IP METHOD #####
            for client in client_list:
                if client.fail_requests >= request and (client.time_blocked is None or client.time_blocked == 'null'):
                    client.time_blocked = str(datetime.datetime.now() + datetime.timedelta(minutes=block_dur))
                    splite_last_dec = client.time_blocked.rpartition('.')
                    client.time_blocked = splite_last_dec[0]
                    block_ip(client.ip_address)

def pareseSSHData(ssh_log_file, parse_ssh):
    #match_list = []
    notin_flag = False
    tail = subprocess.Popen(('tail', '--lines=25', ssh_log_file), stdout=subprocess.PIPE)
    for line in tail.stdout:
        #print line
	for match in re.finditer(parse_ssh, line, re.S):
	    match_text = match.group()

            search_IP = re.search(parse_IP, line, re.S)
	    match_IP = search_IP.group()
	        
	        ##### PARSE THE TIME######
	    search_time = re.search(parse_ssh_time, line, re.S)
            time_tried = search_time.group()
            time_tried = SSH_datetime(time_tried)
	            
	            ##### CHECK THE IP ADDRESS IN THE client_list IF IT EXISTS ######
	    for client in client_list:
                if client.ip_address == match_IP and client.last_time_incr != time_tried:
	            client.fail_requests = client.fail_requests + 1
	            client.last_time_incr = time_tried
		    notin_flag = True
	    if notin_flag == False:
	        newclient = Client(match_IP, time_tried, 1, None, False, time_tried)
	        client_list.append(newclient)
	    notin_flag = False

	            ##### IF THE NUMBERS OF REQUESTED IS OVER THE LIMITE #####
	            ##### CALL BLOCK IP METHOD #####
	    for client in client_list:
	        if client.fail_requests >= request and (client.time_blocked is None or client.time_blocked == 'null'):
                    client.time_blocked = str(datetime.datetime.now() + datetime.timedelta(minutes=block_dur))
	            splite_last_dec = client.time_blocked.rpartition('.')
                    client.time_blocked = splite_last_dec[0]
	            block_ip(client.ip_address)

parseApacheData(log_file_path, parse_WP, parse_jm, parse_php, parse_IP)
pareseSSHData(ssh_log_file, parse_ssh)



#######################CHECK THROUGH THE LIST, SEE IF ANY CAN BE UNBLOCKED#######################
if len(client_list) != 0:
    for c in client_list:
        firstlogintime = datetime.datetime.strptime(c.first_login, "%Y-%m-%d %H:%M:%S")
	time_diff = datetime.datetime.now() - firstlogintime
        time_diff_min = int(round(time_diff.total_seconds()/60))
        if c.remove_blacklist == True:
            client_list.remove(c)
            unblock_ip(c.ip_address)
        if c.time_blocked is not None and c.time_blocked != 'null':
            blocked = datetime.datetime.strptime(c.time_blocked, "%Y-%m-%d %H:%M:%S")
            if datetime.datetime.now() >= blocked:
                client_list.remove(c)
                unblock_ip(c.ip_address)
        if time_diff_min >= request_window and (c.time_blocked is None or c.time_blocked == 'null'):
	    print 'removing client with ip = '
	    print c.ip_address
            client_list.remove(c)
#print("current client list is: " + client_list)         


############################WRITE TO JSON################################
client = []
for c in client_list:
    x = {
        "ipaddress" : c.ip_address,
        "firstlogin" : c.first_login,
        "failedrequests" : c.fail_requests,
        "timeblocked" : c.time_blocked,
        "removeblacklist": c.remove_blacklist,
	"lasttimeincr": c.last_time_incr
    }
    client.append(x)
    #y = json.dumps(x)

#print(client)

client_dic = {"clients" : client}
#print(client_dic)

admin = {
    "requestlimit" : request,
    "requestwindow" : request_window,
    "blockduration" : block_dur
}

info = {
    "admindata" : admin,
    "clientdata" : client_dic
}

#print(info)

#info_json = json.dumps(info)

#print(info_json)

with open("/home/ubuntu/Documents/cse331/myapp/clientdata.json", "w") as outfile:
    json.dump(info, outfile, indent = 4)


outfile.close()
data_json_file.close()
