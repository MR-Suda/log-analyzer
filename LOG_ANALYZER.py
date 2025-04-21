#!/usr/bin/env python3

# PYTHON FUNDAMENTALS | PROJECT: LOG ANALYZER
# Student Name: Shimon
# Program Code: XE103
# Class Code: RTX
# Lecturer: 

import os
import sys
import time
from getpass import getpass
import subprocess
import tempfile

# Function to restrict the user to run the script only with root privileges and check for a password.
def check_root_and_Password():
	
	if os.geteuid() != 0:
		print("\n\033[91m[-]\033[0m This script must be run as root.")
		time.sleep(3)
		os.system("clear")
		sys.exit(1)
			
	print("\n\033[92m[+]\033[0m You have root privileges! Please enter the passcode")
	
	password = "mrsuda"
	attempts = 3
		
	for i in range(attempts):
		entered = getpass("\n- ")
	
		if entered == password:
			print("\n\033[92m[+]\033[0m Correct, access granted.")
			time.sleep(3)
			os.system("clear")
			return True
	
		else:
			remaining = attempts - i - 1
			print(f"\n\033[91m[-]\033[0m Wrong password. Attempts left - {remaining}")
		
	print ("\n\033[91m[!]\033[0m Too many failed attempts. Exiting!")
	time.sleep(3)
	os.system("clear")
	sys.exit(1)

# Banner function.
def banner():
	print("\n\033[95m" + "="*60)
	print("   __        __   _                             _             ")
	print("   \\ \\      / /__| | ___ ___  _ __ ___   ___   | |_ ___       ")
	print("    \\ \\ /\\ / / _ \\ |/ __/ _ \\| '_ ` _ \\ / _ \\  | __/ _ \\  ")
	print("     \\ V  V /  __/ | (_| (_) | | | | | |  __/  | || (_) |      ")
	print("      \\_/\\_/ \\___|_|\\___\\___/|_| |_| |_|\\___|   \\__\\___/ ")
	print("                    LOG ANALYZER - XE105                     ")
	print("="*60 + "\033[0m\n")
	
# Function to ask the user for the auth log they want to analyze.
def select_auth_log():
	while True:
		print("\n\033[96m[~]\033[0m How would you like to select the 'auth.log' file?")
		print ()
		print("\033[92m[1]\033[0m Enter the full path manually")
		print("\033[92m[2]\033[0m Search your system for available 'auth.log' files\n")

		choice = input("Enter [1/2] - ").strip()

		if choice == "1":
			while True:
				path = input("\nType the full path to the 'auth.log' file - ").strip()
				if os.path.isfile(path) and os.access(path, os.R_OK):
					print(f"\n\033[92m[+]\033[0m Using - \033[38;5;208m{path}\033[0m")
					return path
				else:
					print("\n\033[91m[-]\033[0m Invalid path or not readable. Please try again.")

		elif choice == "2":
			print("\n\033[96m[~]\033[0m Searching your system...\n")
			result = os.popen("find / -type f -name 'auth.log' 2>/dev/null").read()
			log_files = result.strip().split("\n")
			log_files = [f for f in log_files if f.strip()]

			if not log_files:
				print("\033[91m[-]\033[0m No 'auth.log' files were found.")
				continue

			print("Found the following 'auth.log' files:\n")
			for i, file in enumerate(log_files, 1):
				print(f"\033[92m[{i}]\033[0m \033[38;5;208m{file}\033[0m")
			
			while True:
				selection = input("\nEnter the number of the file you want to use - ").strip()
				if selection.isdigit():
					index = int(selection) - 1
					if 0 <= index < len(log_files):
						path = log_files[index]
						print(f"\n\033[92m[+]\033[0m Using - \033[38;5;208m{path}\033[0m")
						return path
				print("\n\033[91m[-]\033[0m Invalid selection. Please enter a valid number.")
		else:
			print("\033[91m[-]\033[0m Invalid choice. Please enter 1 or 2.")

# Function to ask for a directory to save output files.
def get_output_directory():
	while True:
		current_dir = os.getcwd()
		print(f"\n\033[96m[~]\033[0m Current directory is - \033[38;5;208m{current_dir}\033[0m")
		choice = input("\nDo you want to use this directory to save output files? [y/n] - ").strip().lower()

		if choice in ["", "y", "yes"]:
			return current_dir

		elif choice in ["n", "no"]:
			while True:
				new_path = input("\nEnter the full path to the directory - ").strip()

				if os.path.isdir(new_path):
					print(f"\n\033[92m[+]\033[0m Directory exists. Using - \033[38;5;208m{new_path}\033[0m")
					return new_path

				else:
					create_choice = input("\n\033[93m[?]\033[0m Directory does not exist. Create it? [y/n] - ").strip().lower()

					if create_choice in ["", "y", "yes"]:
						try:
							os.makedirs(new_path)
							print(f"\n\033[92m[+]\033[0m Directory created. Using - \033[38;5;208m{new_path}\033[0m")
							return new_path
						except Exception as e:
							print(f"\n\033[91m[-]\033[0m Failed to create directory! (Maybe alredy exists ?){e}")
							continue
					else:
						print("\n\033[96m[~]\033[0m Okay, let's try again.")
		else:
			print("\n\033[91m[-]\033[0m Invalid choice. Please enter [y/n].")

# Function to extract command usage to a file.
def command_usage(output_dir, log_path, output_file):
		with open(output_file, "a") as f:
			f.write("==========================         COMMAND USAGE           ==========================\n\n")
			f.write("Date & Time                      | User     | Command\n")
			f.write("---------------------------------|----------|------------------------------------------------------------\n")

		command = (
			f'grep "COMMAND=" "{log_path}" | awk \'{{'
			f'match($0, /^([0-9]{{4}}-[0-9:T.+-]+) kali/, ts); '
			f'date=ts[1]; '
			f'match($0, /COMMAND=.*$/, cmd); '
			f'match($0, /COMMAND=.*USER=([a-zA-Z0-9_-]+)/, u); '
			f'user=(u[1] != "") ? u[1] : "root"; '
			f'printf "%-32s | %-8s | %s\\n", date, user, cmd[0] '
			f'}}\' >> "{output_file}"'
		)

		try:
			subprocess.run(command, shell=True, check=True)
			print(f"\n\033[92m[+]\033[0m Section added: 'COMMAND USAGE'")
		except subprocess.CalledProcessError as e:
			print(f"\n\033[91m[-]\033[0m Failed to append 'COMMAND USAGE'. Error - {e}")
		time.sleep(3)

# Function to extract added or deleted users.
def user_add_delete(output_dir, log_path, output_file):
	awk_code = """
BEGIN {
	print ""
	print "==========================      USER ACCOUNT CHANGES       =========================="
	print ""
	print "Date & Time                      | Action   | User"
	print "---------------------------------|----------|------------------------"
}
{
	match($0, /^([A-Z][a-z]{2} [ 0-9]{1,2} [0-9:]{8}|[0-9]{4}-[0-9:T:+.-]+)/, dt)
	date = (dt[1] != "") ? dt[1] : "Unknown"
	username = "-"
	if ($0 ~ /delete user/) {
		action = "Deleted"
		if (match($0, /delete user '([^']+)'/, m)) username = m[1]
	} else if ($0 ~ /failed adding user/) {
		action = "Failed"
		if (match($0, /failed adding user '([^']+)'/, m)) username = m[1]
	} else if ($0 ~ /new user: name=/) {
		action = "Added"
		if (match($0, /name=([^ ,'"]+)/, m)) username = m[1]
	} else next
	printf "%-32s | %-8s | %s\\n", date, action, username
}
"""

	with tempfile.NamedTemporaryFile("w", delete=False) as temp_awk:
		temp_awk.write(awk_code)
		awk_path = temp_awk.name

	command = (
		f'grep -Ei "useradd.*new user|useradd.*failed adding user|userdel.*delete user" "{log_path}" | '
		f'awk -f "{awk_path}" >> "{output_file}"'
	)

	try:
		subprocess.run(command, shell=True, check=True)
		print(f"\n\033[92m[+]\033[0m Section added: 'USER ACCOUNT CHANGES'")
	except subprocess.CalledProcessError as e:
		print(f"\n\033[91m[-]\033[0m Failed to append 'USER ACCOUNT CHANGES'. Error - {e}")
	finally:
		os.remove(awk_path)

	time.sleep(3)

# Function to extract password changes.
def password_changes(log_path, output_file):
	with open(output_file, "a") as f:
		f.write("\n\n==========================        PASSWORD CHANGES         ==========================\n\n")
		f.write("Date & Time                      | User     | Action\n")
		f.write("---------------------------------|----------|----------------------\n")

	command = (
		f'grep "password changed for" "{log_path}" | awk \'{{'
		f'match($0, /^([0-9]{{4}}-[0-9:T.+-]+)/, dt); '
		f'match($0, /password changed for ([a-zA-Z0-9._-]+)/, u); '
		f'if (dt[1] && u[1]) '
		f'printf "%-32s | %-8s | %s\\n", dt[1], u[1], "Password changed" '
		f'}}\' >> "{output_file}"'
	)

	try:
		subprocess.run(command, shell=True, check=True)
		print(f"\n\033[92m[+]\033[0m Section added: 'PASSWORD CHANGES'")
	except subprocess.CalledProcessError as e:
		print(f"\n\033[91m[-]\033[0m Failed to append 'PASSWORD CHANGES'. Error - {e}")
	
	time.sleep(3)

# Function to extract su and sudo usage.
def privilege_escalation(log_path, output_file):
	with open(output_file, "a") as f:
		f.write("\n\n========================== PRIVILEGE ESCALATION ATTEMPTS   ==========================\n\n")
		f.write("Date & Time                      | Privilege | Command\n")
		f.write("---------------------------------|-----------|------------------------------\n")

	command = (
		f'grep -Ei "sudo:|su:" "{log_path}" | awk \'{{'
		f'match($0, /^([0-9]{{4}}-[0-9:T.+-]+)/, dt); '
		f'if ($0 ~ /sudo:.*COMMAND=/) {{ '
		f'    priv = "sudo"; '
		f'    match($0, /COMMAND=(.*)/, cmd); '
		f'    cmd_out = cmd[1]; '
		f'}} else if ($0 ~ /su:/) {{ '
		f'    priv = "su"; '
		f'    cmd_out = "-"; '
		f'}} else next; '
		f'if (dt[1]) printf "%-32s | %-9s | %s\\n", dt[1], priv, cmd_out; '
		f'}}\' >> "{output_file}"'
	)

	try:
		subprocess.run(command, shell=True, check=True)
		print(f"\n\033[92m[+]\033[0m Section added: 'PRIVILEGE ESCALATION ATTEMPTS'")
	except subprocess.CalledProcessError as e:
		print(f"\n\033[91m[-]\033[0m Failed to append 'PRIVILEGE ESCALATION ATTEMPTS'. Error - {e}")
	time.sleep(3)

# Function to extract failed sudo attempts.
def sudo_failures(output_dir, log_path, output_file):
	with open(output_file, "a") as f:
		f.write("\n\n==========================          SUDO FAILURES          ==========================\n\n")
		f.write("Date & Time                      | User     | Command\n")
		f.write("---------------------------------|----------|------------------------------\n")

	command = (
		f'grep "sudo:" "{log_path}" | grep "authentication failure" | awk \'{{'
		f'match($0, /^([0-9]{{4}}-[0-9:T.+-]+)/, dt); '
		f'match($0, /user=([a-zA-Z0-9._-]+)/, user); '
		f'match($0, /COMMAND=(.*)/, cmd); '
		f'if (dt[1] && user[1]) {{ '
		f'    printf "%-32s | %-8s | %s\\n", dt[1], user[1], (cmd[1] ? cmd[1] : "-"); '
		f'}}'
		f'}}\' >> "{output_file}"'
	)

	try:
		subprocess.run(command, shell=True, check=True)
		print(f"\n\033[92m[+]\033[0m Section added: 'SUDO FAILURES'")
	except subprocess.CalledProcessError as e:
		print(f"\n\033[91m[-]\033[0m Failed to append 'SUDO FAILURES'. Error - {e}")
	time.sleep(3)

# Function to show suspicious activity related to brute-force attempts.
def brute_force_attempts(log_path, output_file):
	with open(output_file, "a") as f:
		f.write("\n\n==========================      BRUTE FORCE ATTEMPTS       ==========================\n\n")
		f.write("Date & Time                      | User     | IP               | Port\n")
		f.write("---------------------------------|----------|------------------|--------\n")

	command = (
		f'grep "Failed password" "{log_path}" | awk \'{{ '
		f'match($0, /^([0-9\\-:T.]+[-+][0-9:]+)/, dt); '
		f'match($0, /Failed password for (invalid user )?([a-zA-Z0-9._-]+)/, u); '
		f'match($0, /from ([0-9.:]+)/, ip); '
		f'match($0, /port ([0-9]+)/, port); '
		f'user = (u[2] != "") ? u[2] : "unknown"; '
		f'ip_addr = (ip[1] == "::1") ? "LocalHost" : ip[1]; '
		f'printf "%-32s | %-8s | %-16s | %-7s\\n", dt[1], user, ip_addr, port[1] '
		f'}}\' >> "{output_file}"'
	)

	try:
		subprocess.run(command, shell=True, check=True)
		print(f"\n\033[92m[+]\033[0m Section added: 'BRUTE FORCE ATTEMPTS'")
	except subprocess.CalledProcessError as e:
		print(f"\n\033[91m[-]\033[0m Failed to append 'BRUTE FORCE ATTEMPTS'. Error - {e}")
	time.sleep(3)

# Function to detect login events from unexpected IP locations.
def detect_unexpected_logins(log_path, output_file):
	with open(output_file, "a") as f:
		f.write("\n\n==========================    UNEXPECTED LOGIN LOCATIONS   ==========================\n\n")
		f.write("Date & Time                      | User     | IP               | Port    | Note\n")
		f.write("---------------------------------|----------|------------------|---------|----------------\n")

	command = (
		f'grep "Accepted password" "{log_path}" | awk \'{{ '
		f'match($0, /^([0-9\\-:T.]+[-+][0-9:]+)/, dt); '
		f'match($0, /Accepted password for ([a-zA-Z0-9._-]+)/, u); '
		f'match($0, /from ([0-9.:]+)/, ip); '
		f'match($0, /port ([0-9]+)/, port); '
		f'user = u[1]; ip_addr = ip[1]; note = "NEW LOCATION"; '
		f'if (ip_addr ~ /^::1$/ || ip_addr ~ /^127/ || ip_addr ~ /^192\\.168/ || ip_addr ~ /^10\\./ || ip_addr ~ /^172\\./) next; '
		f'printf "%-32s | %-8s | %-16s | %-7s | %s\\n", dt[1], user, ip_addr, port[1], note '
		f'}}\' >> "{output_file}"'
	)

	try:
		subprocess.run(command, shell=True, check=True)
		print(f"\n\033[92m[+]\033[0m Section added: 'UNEXPECTED LOGIN LOCATIONS'")
	except subprocess.CalledProcessError as e:
		print(f"\n\033[91m[-]\033[0m Failed to append 'UNEXPECTED LOGIN LOCATIONS'. Error - {e}")
	time.sleep(3)

# Function to detect unusual or potentially malicious command executions.
def detect_unusual_commands(auth_log_path, output_path):

	suspicious_patterns = (
		'nc|bash -i|python.*pty|/bin/sh|curl|wget|socat|nmap|netcat|reverse|/dev/tcp|/dev/udp|'
		'telnet|ftp|perl|php|ruby|scp|sshpass|tftp|rm'
	)
	
	awk_script = r'''
	{
		match($0, /^([0-9\-:T.]+-[0-9:]+)/, dt)
		match($0, /sudo:\s+(\w+)/, usr)
		match($0, /COMMAND=(.*)/, cmd)
		if (dt[1] && usr[1] && cmd[1]) {
			printf "%-32s | %-10s | %s\n", dt[1], usr[1], cmd[1]
		}
	}
	'''
	
	cmd = f'''grep "COMMAND=" "{auth_log_path}" | grep -Ei '{suspicious_patterns}' | awk '{awk_script}' '''
	
	try:
		result = subprocess.check_output(cmd, shell=True, text=True)
		
		with open(output_path, "a") as f:
			f.write("\n\n==========================     UNUSUAL COMMAND EXECUTION   ==========================\n\n")
			f.write("Date & Time                      | User       | Command\n")
			f.write("---------------------------------|------------|------------------------------\n")
			f.write(result)
			f.write("\n" + "-" * 75 + "\n")

		print(f"\n\033[92m[+]\033[0m Section added: 'UNUSUAL COMMAND EXECUTIONS'")
	except subprocess.CalledProcessError as e:
		print(f"\n\033[91m[-]\033[0m Failed to append 'UNUSUAL COMMAND EXECUTIONS'. Error - {e}")
		time.sleep(3)

# Function to generate a final summary section in the report.
def generate_summary_report(auth_log_path, output_path):
	try:
		with open(auth_log_path, "r") as log_file:
			log_data = log_file.read()

		total_commands     = log_data.count("COMMAND=")
		users_added        = log_data.count("useradd") + log_data.count("new user:")
		users_deleted      = log_data.count("userdel")
		password_changes   = log_data.count("passwd") + log_data.count("password changed")
		priv_esc_events    = log_data.count("session opened for user root")
		sudo_failures      = log_data.count("sudo:") and log_data.count("authentication failure")

		summary_section = f"""
==========================             SUMMARY             ==========================

Total Commands Logged:  {total_commands}
User Accounts Added:    {users_added}
User Accounts Deleted:  {users_deleted}
Password Changes:       {password_changes}
Privilege Escalations:  {priv_esc_events}
Sudo Failures:          {sudo_failures}

{"=" * 83}
"""

		with open(output_path, "a") as f:
			f.write(summary_section)

		print("\n\033[92m[+]\033[0m Summary section added successfully.")
	
	except Exception as e:
		print(f"\n\033[91m[-]\033[0m Failed to generate summary. Error: {e}")
		
# Function to ask the user if they want to view the final report.
def prompt_to_view_report(output_file):
	while True:
		choice = input("\n\033[96m[?]\033[0m Would you like to view the report now? [y/n] - ").strip().lower()
		if choice in ["y", "yes", ""]:
			print(f"\n\033[96m[~]\033[0m Displaying contents of: \033[38;5;208m{output_file}\033[0m\n")
			with open(output_file, "r") as f:
				print(f.read())
				print("\n\033[92m[+]\033[0m Done. Report saved.")
			break
		elif choice in ["n", "no"]:
			print("\n\033[92m[+]\033[0m Done. Report saved.")
			break
		else:
			print("\033[91m[-]\033[0m Invalid input. Please enter [y/n].")

# Call main functions and capture important variables
try:
	if check_root_and_Password():
		banner()
		log_path = select_auth_log()
		output_dir = get_output_directory()
		shared_log = os.path.join(output_dir, "Log_Analyzer_Report.log")

		command_usage(output_dir, log_path, shared_log)
		user_add_delete(output_dir, log_path, shared_log)
		password_changes(log_path, shared_log)
		privilege_escalation(log_path, shared_log)
		sudo_failures(output_dir, log_path, shared_log)
		brute_force_attempts(log_path, shared_log)
		detect_unexpected_logins(log_path, shared_log)
		detect_unusual_commands(log_path, shared_log)
		generate_summary_report(log_path, shared_log)
		prompt_to_view_report(shared_log)

# Function to handle Ctrl+C interruptions.
except KeyboardInterrupt:
	print("\n\n\033[91m[!]\033[0m Interrupted by user. Exiting gracefully...\n")
	sys.exit(0)
