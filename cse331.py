import re
import time
from time import strftime
import subprocess
import json


##########READ PREPROCESSES FILE############
class Client:
    def __init__(self, ip_address, first_login, fail_requests, time_blocked):
        self.ip_address = ip_address
        self.first_login = first_login
        self.fail_requests = fail_requests
        self.time_blocked = time_blocked

with open("/usr/share/modips/data/clientdata.json") as data_json_file:
    data = json.load(data_json_file)
    admindata = data['admindata']
    request = admindata['requestlimit']
    request_window = admindata['requestwindow']
    block_dur = admindata['blockduration']
    clientdata = data['clientdata']
    client_list = []
    for c in clientdata.values():
        client = Client()
        client.ip_address = c['ipaddress']
        client.first_login = c['firstlogin']
        client.failed_requests = c['failedrequests']
        client.time_blocked = c['timeblocked']
        client_list.append(client)


def block_ip(ip):
    cmd="iptables -A INPUT -s "+ip+" -j DROP"
    #print cmd
    subprocess.call(cmd,shell=True)


   
        

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
parse_ssh_time = '(\w{3} \d{2} \d{2}:\d{2}:\d{2})'


def parseApacheData(log_file_path, parse_WP, parse_jm, parse_php, parse_IP):
    #match_list = []
    notin_flag = False
    with open(log_file_path, "r") as file:
        for line in file:
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
                    if client.ip_address == match_IP:
                        client.fail_requests + 1
                        notin_flag = True
                if notin_flag == False:
                    newclient = Client(match_IP, time_tried, 1, None)
                    client_list.append(newclient)
                notin_flag = False

                ##### IF THE NUMBERS OF REQUESTED IS OVER THE LIMITE #####
                ##### CALL BLCOK IP METHOD #####
                for client in client_list:
                    if client.fail_requests >= request:
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
                    if client.ip_address == match_IP:
                        client.fail_requests + 1
                        notin_flag = True
                if notin_flag == False:
                    newclient = Client(match_IP, time_tried, 1, None)
                    client_list.append(newclient)
                notin_flag = False

                    ##### IF THE NUMBERS OF REQUESTED IS OVER THE LIMITE #####
                    ##### CALL BLCOK IP METHOD #####
                for client in client_list:
                    if client.fail_requests >= request:
                        block_ip(client.ip_address)
                    #ip_dict(match_IP)


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
                    if client.ip_address == match_IP:
                        client.fail_requests + 1
                        notin_flag = True
                if notin_flag == False:
                    newclient = Client(match_IP, time_tried, 1, None)
                    client_list.append(newclient)
                notin_flag = False

                    ##### IF THE NUMBERS OF REQUESTED IS OVER THE LIMITE #####
                    ##### CALL BLCOK IP METHOD #####
                for client in client_list:
                    if client.fail_requests >= request:
                        block_ip(client.ip_address)
                    #ip_dict(match_IP)
    file.close()

def pareseSSHData(ssh_log_file, parse_ssh):
    #match_list = []
    notin_flag = False
    with open(ssh_log_file, "r") as file:
    for line in file:
        for match in re.finditer(parse_ssh, line, re.S):
            match_text = match.group()
            #match_list.append(match_text)
            search_IP = re.search(parse_IP, line, re.S)
            match_IP = search_IP.group()
            #print(match_IP)
            ##### PARSE THE TIME######
            search_time = re.search(parse_ssh_time, line, re.S)
            time_tried = search_time.group()
            time_tried = SSH_datetime(time_tried)
            #print(time_tried)
            ##### CHECK THE IP ADDRESS IN THE client_list IF IT EXISTS ######
            for client in client_list:
                if client.ip_address == match_IP:
                    client.fail_requests + 1
                    notin_flag = True
            if notin_flag == False:
                newclient = Client(match_IP, time_tried, 1, None)
                client_list.append(newclient)
            notin_flag = False

            ##### IF THE NUMBERS OF REQUESTED IS OVER THE LIMITE #####
            ##### CALL BLOCK IP METHOD #####
            for client in client_list:
                #print(client.fail_requests)
                if client.fail_requests >= request:
                    block_ip(client.ip_address)
            #ip_dict(match_IP)
            #print match_list
file.close()

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
    retuen date
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

    result='2018-'+month+'-'+timeList[1]
    return result


#######################CHECK THROUGH THE LIST, SEE IF ANY CAN BE UNBLOCKED#######################
if len(client_list) != 0:
    for c in client_list:
        blocked = datetime.strptime(c.time_blocked, "%Y-%m-%d %H:%M:%S")
        if datetime.now() >= blocked:
            client_list.remove(c)
#print("current client list is: " + client_list)         


############################WRITE TO JSON################################





data_json_file.close()
