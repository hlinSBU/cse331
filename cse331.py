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

time_now = str(strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
#######################CHECK THROUGH THE LIST, SEE IF ANY CAN BE UNBLOCKED#######################






###########READ LOG_FILE############
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
    match_list = []
    notin_flag = False
    with open(log_file_path, "r") as file:
        for line in file:
            for match in re.finditer(parse_WP, line, re.S):
                match_text = match.group()
                match_list.append(match_text)
                match_IP = re.finditer(parse_IP, line, re.S)
                ##### PARSE THE TIME######
                time_tried = re.finditer(parse_time, match_text, re.S)
                ##### CHECK THE IP ADDRESS IN THE client_list IF IT EXISTS ######
                for client in client_list:
                    if client.ip_address == match_IP:
                        client.fail_requests + 1
                        notin_flag = True
                if notin_flag == False:
                    new_client = Client()
                    new_client.ip_address = match_IP
                    new_client.first_login = time_tried
                    new_client.fail_requests = 1
                    new_client.time_blocked = None
                    client_list.append(new_client)
                notin_flag = False

                ##### IF THE NUMBERS OF REQUESTED IS OVER THE LIMITE #####
                ##### CALL BLCOK IP METHOD #####
                for client in client_list:
                    if client.fail_requests >= request_window:
                        blcok_ip(client.ip_address)
                ip_dict(match_IP)

            for match in re.finditer(parse_jm, line, re.S):
                match_text = match.group()
                match_list.append(match_text)
                match_IP = re.finditer(parse_IP, line, re.S)
                ##### PARSE THE TIME######
                time_tried = re.finditer(parse_time, match_text, re.S)
                ##### CHECK THE IP ADDRESS IN THE client_list IF IT EXISTS ######
                for client in client_list:
                    if client.ip_address == match_IP:
                        client.fail_requests+1
                        notin_flag = True
                if notin_flag == False:
                    new_client = Client()
                    new_client.ip_address = match_IP
                    new_client.first_login = time_tried
                    new_client.fail_requests = 1
                    new_client.time_blocked = None
                    client_list.append(new_client)
                notin_flag = False

                ##### IF THE NUMBERS OF REQUESTED IS OVER THE LIMITE #####
                ##### CALL BLCOK IP METHOD #####
                for client in client_list:
                    if client.fail_requests >= request_window:
                        blcok_ip(client.ip_address)
                ip_dict(match_IP)

            for match in re.finditer(parse_php, line, re.S):
                match_text = match.group()
                match_list.append(match_text)
                match_IP = re.finditer(parse_IP, match_text, re.S)
                ##### PARSE THE TIME######
                time_tried = re.finditer(parse_time, match_text, re.S)
                ##### CHECK THE IP ADDRESS IN THE client_list IF IT EXISTS ######
                for client in client_list:
                    if client.ip_address == match_IP:
                        client.fail_requests + 1
                        notin_flag = True
                if notin_flag == False:
                    new_client = Client()
                    new_client.ip_address = match_IP
                    new_client.first_login = time_tried
                    new_client.fail_requests = 1
                    new_client.time_blocked = None
                    client_list.append(new_client)
                notin_flag = False

                ##### IF THE NUMBERS OF REQUESTED IS OVER THE LIMITE #####
                ##### CALL BLCOK IP METHOD #####
                for client in client_list:
                    if client.fail_requests >= request_window:
                        blcok_ip(client.ip_address)
                ip_dict(match_IP)
                #print match_list
    file.close()

def pareseSSHData(ssh_log_file, parse_ssh):
    match_list = []
    with open(ssh_log_file, "r") as file:
        for line in file:
            for match in re.finditer(parse_ssh, line, re.S):
                match_text = match.group()
                match_list.append(match_text)
                match_IP = re.finditer(parse_IP, line, re.S)
                                ##### PARSE THE TIME######
                time_tried = re.finditer(parse_time, match_text, re.S)
                ##### CHECK THE IP ADDRESS IN THE client_list IF IT EXISTS ######
                for client in client_list:
                    if client.ip_address == match_IP:
                        client.fail_requests + 1
                        notin_flag = True
                if notin_flag == False:
                    new_client = Client()
                    new_client.ip_address = match_IP
                    new_client.first_login = time_tried
                    new_client.fail_requests = 1
                    new_client.time_blocked = None
                    client_list.append(new_client)
                notin_flag = False

                ##### IF THE NUMBERS OF REQUESTED IS OVER THE LIMITE #####
                ##### CALL BLCOK IP METHOD #####
                for client in client_list:
                    if client.fail_requests >= request_window:
                        blcok_ip(client.ip_address)
                ip_dict(match_IP)
                #print match_list
    file.close()

def ip_dict(ip):
    ######CHECK TIME IF THE IP SHOULD BE ADD TO dict_check ######
    if ip in dict_check:
        dict_check[ip]+1
    else:
        dict_check[ip] = 1

def blcok_ip(ip):
    cmd="iptables -A INPUT -s "+ip+" -j DROP"
    #print cmd
    subprocess.call(cmd,shell=True)


############################WRITE TO JSON################################


data_json_file.close()