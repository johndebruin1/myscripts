#!/bin/python3
import os
import signal
import time
import requests
import json
from getpass import getpass
import random
import string
import subprocess
import logging
from pathlib import Path
import sys
def run_command(command):
	"""Run a command using subprocess and return the output."""
	result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	if result.returncode != 0:
		raise Exception(f"Command failed with error: {result.stderr.decode().strip()}")
		return result.stdout.decode().strip()

def login_to_bitwarden():
	"""Login to Bitwarden using API key."""
	# Log in to Bitwarden using the CLI
	try:
		print(">>INFO: Logging in to Bitwarden...", end= " ")
		login_output = run_command('./bw login --apikey')
		return True
	except Exception as e:
		print(f"An error occurred: {e}")
		return False

def apiLogin():
	# Read the JSON file
	with open(Path.home()/".bitwarden", "r") as json_file:
		credentials = json.load(json_file)
		json_file.close()
	# Set your Bitwarden API credentials from the JSON file
	BW_CLIENTID = os.getenv('BW_CLIENTID', credentials["Client_ID"])
	BW_CLIENTSECRET = os.getenv('BW_CLIENTSECRET', credentials["Client_Secret"])
	# Ensure the environment variables are set
	os.environ['BW_CLIENTID'] = BW_CLIENTID
	os.environ['BW_CLIENTSECRET'] = BW_CLIENTSECRET
	if __name__ == "__main__":
		success = login_to_bitwarden()
		if success == True:
			print("Login Successful")

def unlockVault(pid):
	print(">>INFO: Unlocking Vault...", end=" ")
	password = getpass()
	url = "http://localhost:8087/unlock"
	payload = json.dumps({
		"password": password})
	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json'
		}
	response = requests.request("POST", url, headers=headers, data=payload)
	if response.status_code != 200:
		print(">>WARNING: Unable to unlock vault w/ provided password, Please try again:")
		password = getpass()
		payload = json.dumps({"password": password})
		response = requests.request("POST", url, headers=headers, data=payload)
		if response.status_code != 200:
			print(">>ERROR: Failed to unlock on second try too.")
			dieNice(pid)
	response_text=response.text
	data=json.loads(response_text)
	title_message = data["data"]["title"]
	print(title_message)

def generatePassword(length=12, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True):
	# Define possible characters
	characters = ''
	if use_uppercase:
		characters += string.ascii_uppercase
	if use_lowercase:
		characters += string.ascii_lowercase
	if use_digits:
		characters += string.digits
	if use_special:
		#characters += string.punctuation
		characters += "!@#$%^&*"
	# Ensure that there is at least one type of character to choose from
	if not characters:
		raise ValueError("At least one character set must be selected")
	# Generate the password
	password = ''.join(random.choice(characters) for _ in range(length))

	return password

def syncBitwarden(pid):
	print(">>INFO: Syncing Bitwarden...", end=" ")
	url = 'http://localhost:8087/sync'
	headers = {
		'Accept': 'application/json',
		}
	response = postBWcall(url,headers,0,pid)
	sync_message = response.json()["data"]["title"]
	print(sync_message)

def oldPassword(server_name):
	url = 'http://localhost:8087/list/object/items'
	params = {
		'collectionIds': '2c294537-1546-41ca-b2dd-b17e010f3d2b',
		'search': server_name
		}
	response = getBWcall(url,params,pid)
	data = response.json()
	if not data['data']['data']:
		params = {
                        'collectionIds': '2c294537-1546-41ca-b2dd-b17e010f3d2b',
                        'search': 'DefaultPass'
			}
		response = getBWcall(url,params,pid)
		data = response.json()
		oldPassword=data['data']['data'][0]['login']['password']
		return oldPassword
	else:
		oldPassword=data['data']['data'][0]['login']['password']
		return oldPassword

def getBWcall(url,params,pid):
	response = requests.get(url, params=params)
	if response.status_code != 200:
		print(">>WARNING: Unable to connect to BW server, trying again in 30 secs:")
		os.system('sleep 30')
		response = requests.get(url, params=params)
		if response.status_code != 200:
			print(">>ERROR: Unable to connect to BW server, failed twice")
			dieNice(pid)
		else:
			return response
	else:
		return response

def postBWcall(url,headers,item_data,pid):
	if(item_data == 0):
		response = requests.post(url, headers=headers)
	else:
		response = requests.post(url, headers=headers, json=item_data)
	if response.status_code != 200:
		print(">>WARNING: Unable to connect to BW server, trying again in 30 secs:")
		#logging.error(f"Error fetching data for server {server_name}. Status code: {response.status_code}")
		os.system('sleep 30')
		if(item_data == 0):
			response = requests.post(url, headers=headers)
		else:
			response = requests.post(url, headers=headers, json=item_data)
		if response.status_code != 200:
			print(">>ERROR: Unable to connect to BW server, failed twice")
			logging.error(f"Error fetching data for server {server_name}. Status code: {response.status_code}")
			dieNice(pid)
		else:
			return response
	else:
		return response

def changePassword(server_name, password, pid):
	print(">>INFO: Changing Bitwarden Password for "+ server_name +"...", end=" ")
	url = 'http://localhost:8087/list/object/items'
	params = {
		'collectionIds': '2c294537-1546-41ca-b2dd-b17e010f3d2b',
		'search': server_name
	 	}
	response = getBWcall(url,params,pid)
	data = response.json()
	itemExists=False
	for i in data['data']['data']:
		if i['name']==server_name:
			# Extract the ID from the data
			item_id = i['id']
			url = 'http://localhost:8087/object/item/'+item_id
			headers = {
				'Content-Type': 'application/json',
				'Accept': 'application/json'
				}
			data = {
				"type": 1,
				"name": server_name,
				"login": {
				"username": "root",
				"password": password,
				"totp": None
				},
				"reprompt": 0
				}
			response = requests.put(url, headers=headers, data=json.dumps(data))
			code=response.status_code
			if code==200:
				print("Done!")
				return("update")
			else:
				# Log the error message
				logging.error(f"Error changing password for server {server_name} in Bitwarden. Status code: {code}, Response: {response.json()}")
				return("fail")
			itemExists=True
	if itemExists==False:
		item_url = 'http://localhost:8087/object/item'
		item_headers = {
			'Content-Type': 'application/json',
			'Accept': 'application/json'
		}
		item_data = {
			"organizationId": "b97d3fb3-4523-4906-b836-affc010c9840",
			"collectionIds": ["2c294537-1546-41ca-b2dd-b17e010f3d2b"],
			"folderId": None,
			"type": 1,
			"name": server_name,
			"notes": None,
			"favorite": False,
			"fields": [{
				"name": None,
				"value": None,
				"type": 0,
				"linkedId": None
			}],
			"login": {
				"fido2Credentials": [],
				"uris": [],
				"username": "root",
				"password": password,
				"totp": None,
				"passwordRevisionDate": "2024-02-08T13:27:22.657Z"
			},
			"reprompt": 0
		}
		response = postBWcall(item_url,item_headers,item_data,pid)
		#requests.post(item_url, headers=item_headers, json=item_data)
		print(server_name, "Created!")
		return("create")


def changeServerPassword(server_name, password, old_password):
	print(">>INFO: Changing root password for " + server_name + "...", end=" ")
	try:
		# Construct the SSH command to change the password
		ssh_command = [
			'sshpass', '-p', old_password,
			'ssh', '-o', 'StrictHostKeyChecking=no', f'root@{server_name}',
			f"echo -e '{password}\n{password}' | passwd root"
		]
		# Execute the SSH command with subprocess
		process = subprocess.Popen(ssh_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
		# Capture stdout and stderr
		output, error = process.communicate()
		# Check if the process completed successfully
		if process.returncode == 0:
			print("Done!")
			return "Success"
		else:
			# Log the error message
			logging.error(f"Error changing password for user root on server {server_name}: {error.strip()}")
			return "Fail"
	except Exception as e:
		# Log the exception
		logging.exception(f"An error occurred while changing password for user root on server {server_name}: {str(e)}")
		return "Fail"

def revertBitwarden(server_name, old_password, pid):
	url = 'http://localhost:8087/list/object/items'
	params = {
		'collectionIds': '2c294537-1546-41ca-b2dd-b17e010f3d2b',
		'search': server_name
		}
	response = getBWcall(url,params,pid)
	data = response.json()
	itemExists=False
	for i in data['data']['data']:
		if i['name']==server_name:
			# Extract the ID from the data
			item_id = i['id']
			url = 'http://localhost:8087/object/item/'+item_id
			headers = {
				'Content-Type': 'application/json',
				'Accept': 'application/json'
				}
			data = {
				"type": 1,
				"name": server_name,
				"login": {
				"username": "root",
				"password": old_password,
				"totp": None
				},
				"reprompt": 0
				}
			response = requests.put(url, headers=headers, data=json.dumps(data))
			code=response.status_code
			if code==200:
				print(server_name, "Password Reverted!")
				return("update")
			else:
				# Log the error message
				logging.error(f"Error reverting password for server {server_name} in Bitwarden. Status code: {code}, Response: {response.json()}")
				return("fail")

def dieNice(pid):
	os.kill(pid, signal.SIGSTOP)
	exit(1)


#Main
# Configure logging
logging.basicConfig(filename='error_log.txt', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
apiLogin()
print(">>INFO: Starting Server...", end=" ")
# Fork the current process
pid = os.fork()
if pid > 0:
	# In the parent process
	logging.error(f"PID: {pid}")
else:
	# In the child process
	pid=os.getpid()
	os.system('/installs/Bitwarden/bw serve')
	quit()
print("Server Started")
#os.system('sleep 10')
unlockVault(pid)
syncBitwarden(pid)
server_names=sys.argv[1:]
items_assigned=0
update_count=0
create_count=0
fail_count=0
servers_updated=0
revert_count=0
for server_name in server_names:
	old_password=oldPassword(server_name)
	password=generatePassword()
	status=changePassword(server_name, password, pid)
	if status == "update":
		if changeServerPassword(server_name, password, old_password) == "Success":
			servers_updated+=1
			update_count+=1
			items_assigned+=1
		else:
			revertBitwarden(server_name, old_password, pid)
			revert_count+=1
			fail_count+=1
	elif status == "create":
		if changeServerPassword(server_name, password, old_password) == "Success":
			servers_updated+=1
			create_count+=1
			items_assigned+=1
		else:
			revertBitwarden(server_name, old_password, pid)
			revert_count+=1
			fail_count+=1
	else:
		fail_count+=1
	#if changeServerPassword(server_name, password) == "Success":
		#servers_updated+=1
		#status=changePassword(server_name, password)
		#if status == "update":
			#update_count+=1
			#items_assigned+=1
		#elif status == "create":
			#create_count+=1
			#items_assigned+=1
		#else:
			#fail_count+=1
	#else:
		#fail_count+=1
print("\n",items_assigned, "Bitwarden Items Assigned: ")
print("---", update_count, "Items Updated")
print("---", create_count, "Items Created")
print(servers_updated, "Servers Updated")
print(fail_count, "Assignments Failed")
print(revert_count, "Items Reverted in Bitwarden")
os.kill(pid, signal.SIGSTOP)
