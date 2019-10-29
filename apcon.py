#This script was created to automate packet captures on APCON whenever the Palo Alto firewall reports receiving fragmented IP packets above a set threshold value.

#Feel free to modify to fit your needs.

#This script assumes that sending and receiving ports and filters are already setup on APCON.
#An aggregation ID from the Record Settings window is required.  

#Requires requests and paramiko packages
#pip install requests paramiko

#usage: $ python3 apcon.py

import smtplib, time, paramiko,urllib3, json, requests, xml.etree.ElementTree as ET
from datetime import datetime
from email.message import EmailMessage

urllib3.disable_warnings()

sleep_timer = 30 #Seconds to pause between polling the firewall and doing packet capture

ip_frag_threshold = 107000 #IP fragmentation threshold, as reported by the firewall, before triggering packet capture

palo_alto_ip = '192.168.100.50' #IP address of the Palo Alto Firewall
palo_alto_api_key = '&key=' #Palo Alto API key. Put AFTER the equal sign

apcon_device_ip = '192.168.200.10' #IP address of the APCON device
apcon_user = '' #Username to log into "WebXR portal"
apcon_password = '' #password
apcon_aggregate_id = 1000 #Aggregate ID from the Record Settings window
apcon_capture_length = 1 #Number of seconds to capture
apcon_capture_filename = "Test_Cap" #Packet capture filename prefix

check_disk_space = False #Set to True to check for enough free disk space before capturing
ssh_host = '192.168.200.11' #IP address of the VM host on IntellaStore blade
ssh_port = 22 #SSH Port of VM host
ssh_username = '' 
ssh_password = ''
disk_space_limit = 95 #Percent disk utilization limit. Will not capture if current disk utilization exceeds this value

send_email = False #Set to true if you want an e-mail alert whenever a packet capture is triggered 
smtp_host = '' #SMTP or relay server to use. 
msg = EmailMessage()
msg['Subject'] = 'Packet Capture Triggered'
msg['From'] = 'from@example.org'
msg['To'] = 'to@example.org'

#Palo Alto API query string. Modify to fit your needs
palo_alto_command='/api/?type=op&cmd=<show><counter><global><filter><aspect>ipfrag</aspect><delta>yes</delta></filter></global></counter></show>'

palo_request_url = 'https://' + palo_alto_ip + palo_alto_command + palo_alto_api_key

while(True):
	palo_alto_response = requests.get(palo_request_url, verify=False)

	tree = ET.fromstring(palo_alto_response.text)
	root = tree.findall('.//entry')

	search_string = 'flow_ipfrag_recv' #Also modify this your specific needs
	search_string_found = False
	ip_frag_value = 0
	for entry in root:
		for dp in entry:
			if dp.text == search_string:
				search_string_found = True
				continue
			if search_string_found == True:
				ip_frag_value = dp.text
				search_string_found = False
				break


	print("Current IP Fragmentation rate = " + str(ip_frag_value))


	if int(ip_frag_value) > ip_frag_threshold:
		current_time = datetime.now()
		timestamp = current_time.strftime('%Y%m%d_%H%M%S')
		capture_filename = apcon_capture_filename + "_" + str(timestamp)

		print("IP Fragmenation rate exceeds threshold of " + str(ip_frag_threshold))

		if check_disk_space == True:
			print("Checking APCON disk space...")
			disk_space = 0
			ssh_client = paramiko.SSHClient()
			ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh_client.connect(ssh_host, ssh_port, ssh_username, ssh_password)
			stdin, stdout, stderr = ssh_client.exec_command("df -h | grep apcon_capture | awk \'{print $5}\' | cut -d\'%\' -f1")
			for line in stdout:
				disk_space = int(line.strip('\n'))
				break
		
			if disk_space > disk_space_limit:
				print("Out of disk space. Skipping capture...")
				continue
			else:
				print(str(disk_space) + "% disk space. Continue to capture")
			

	
		apcon_login_url = "https://" + apcon_device_ip + "/APCON/v1/login?format=jsonp&HTTP_METHOD=POST&username=" + apcon_user + "&password=" + apcon_password

		apcon_login = requests.get(apcon_login_url, verify=False)

		apcon_login_json = apcon_login.json()

		apcon_auth_token = apcon_login_json['authToken']

		apcon_create_capture_url = "https://" + apcon_device_ip + "/APCON/v1/captures/" + str(apcon_aggregate_id) + "?format=jsonp&HTTP_METHOD=POST&enabled=True&pcapFileName=" + capture_filename + "&captureFileFormat=pcap&scheduleType=None&maxTime=" + str(apcon_capture_length) + "&authToken=" + apcon_auth_token

		apcon_create_capture_response = requests.get(apcon_create_capture_url, verify=False)

		print("Setting up packet capture for " + str(apcon_capture_length) + " seconds")
		print(apcon_create_capture_response.text)

		apcon_capture_url = "https://" + apcon_device_ip + "/APCON/v1/captures/" + str(apcon_aggregate_id) + "?format=jsonp&HTTP_METHOD=POST&status=True" + "&authToken=" + apcon_auth_token

		apcon_capture_response = requests.get(apcon_capture_url, verify=False)

		print("Capturing...")
		print(apcon_capture_response.text)

		if send_email == True:
			msg.set_content('Packet Capture Triggered at: ' + str(timestamp) + '\nFragmentation rate: ' + str(ip_frag_value))
			s = smtplib.SMTP(smtp_host)
			s.send_message(msg)
			s.quit()

	print("Sleep for " + str(sleep_timer) + " seconds")
	time.sleep(sleep_timer)
	
