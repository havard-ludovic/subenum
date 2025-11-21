#!/usr/bin/env python3
"""
subenum.py -- parallel reconnaissance launcher for bug-bounty recon

Usage:
    python3 subenum.py target.com
    python3 subenum.py target.com -o /path/to/output/directory

Notes:
 - This script checks that required binaries are installed (amass, gobuster,
   subfinder, assetfinder, docker, httpx-toolkit, dnsx). If any are missing the script exits.
 - The script launches tools in parallel and does not impose a timeout.
 - Output files are written to the specified output directory (defaults to current directory).
 - Use only on targets you are authorized to test.
"""

import argparse
import shutil
import subprocess
import shlex
import sys
from pathlib import Path
import re

REQUIRED_TOOLS = ["amass", "gobuster", "subfinder", "assetfinder", "docker", "httpx-toolkit", "dnsx"]

def check_tools():
	"""Return list of missing tools (empty list if all present)."""
	missing = []
	for tool in REQUIRED_TOOLS:
		if shutil.which(tool) is None:
			missing.append(tool)
	return missing

def check_wordlists(wordlist1: str, wordlist2: str):
    wl1 = Path(wordlist1)
    wl2 = Path(wordlist2)

    missing = []

    if not wl1.is_file():
        missing.append(wordlist1)

    if not wl2.is_file():
        missing.append(wordlist2)

    if missing:
        print("[!] Error: The following wordlists were not found:")
        for wl in missing:
            print(f"    - {wl}")
        print("[!] Fix the paths or install the required wordlists before running again.")
        sys.exit(1)

    print("[+] Wordlists verified successfully.")

def launch_shell_command(cmd, friendly_name):
	"""
	Launch a shell command string with shell=True and return the Popen object.
	We intentionally do not set a timeout here (no timeout).
	"""
	print(f"[+] Starting: {friendly_name}")
	proc = subprocess.Popen(cmd, shell=True)
	return proc

def make_commands(target, outdir: Path, gobuster_wordlist_1, gobuster_wordlist_2):
	"""Build shell command strings with outputs redirected into outdir."""
	qtarget = shlex.quote(target)
	# prepare quoted output filenames
	amass_subs_file = shlex.quote(str(outdir / "amass.txt"))
	gob1_file = shlex.quote(str(outdir / "gobuster1.txt"))
	gob2_file = shlex.quote(str(outdir / "gobuster2.txt"))
	subfinder_file = shlex.quote(str(outdir / "subfinder.txt"))
	assetfinder_file = shlex.quote(str(outdir / "assetfinder.txt"))
	findomain_file = shlex.quote(str(outdir / "findomain.txt"))

	# amass: enum then subs -> two files (enum output and subs)
	cmd_amass = (
		f'amass enum -d {qtarget} -active -alts -brute -nocolor '
		f'-min-for-recursive 2 -timeout 60 '
		f'-r 8.8.8.8 -r 1.1.1.1 -r 9.9.9.9 -r 64.6.64.6 '
		f'-r 208.67.222.222 -r 208.67.220.220 -r 8.26.56.26 '
		f'-r 8.20.247.20 -r 185.228.168.9 -r 185.228.169.9 '
		f'-r 76.76.19.19 -r 76.223.122.150 -r 198.101.242.72 '
		f'-r 176.103.130.130 -r 176.103.130.131 -r 94.140.14.14 '
		f'-r 94.140.15.15 -r 1.0.0.1 -r 77.88.8.8 -r 77.88.8.1 '
		f'-rqps 10 && amass subs -names -d {qtarget} -ip > {amass_subs_file}'
	)

	# Gobuster DNS scans (wordlists must exist on system)
	cmd_gob1 = (
		f'gobuster dns -domain {qtarget} '
		f'-w {gobuster_wordlist_1} '
		f'-ne -t 100 --wildcard --resolver 8.8.8.8 -o {gob1_file}'
	)

	cmd_gob2 = (
		f'gobuster dns -domain {qtarget} '
		f'-w {gobuster_wordlist_2} '
		f'-ne -t 100 --wildcard --resolver 1.1.1.1 -o {gob2_file}'
	)

	cmd_subfinder = f'subfinder -d {qtarget} -o {subfinder_file}'
	cmd_assetfinder = f'assetfinder --subs-only {qtarget} > {assetfinder_file}'

	# Docker-based findomain: pull image, run container (stdout redirected to host file), then remove image
	cmd_findomain = (
		f'docker pull edu4rdshl/findomain:latest && '
		f'docker run --rm edu4rdshl/findomain -t {qtarget} > {findomain_file} && '
		f'docker rmi edu4rdshl/findomain:latest'
	)

	tasks = [
		(cmd_amass, "amass"),
		(cmd_gob1, "gobuster1"),
		(cmd_gob2, "gobuster2"),
		(cmd_subfinder, "subfinder"),
		(cmd_assetfinder, "assetfinder"),
		(cmd_findomain, "findomain (docker)"),
	]
	return tasks

def run_post_processing(target, outdir: Path):
	ip_file = shlex.quote(str(outdir / "ips.txt"))
	dnsx_file = shlex.quote(str(outdir / "dnsx.txt"))
	live_subs_file = shlex.quote(str(outdir / "live_subs.txt"))
	httpx_output_file = shlex.quote(str(outdir / "httpx_output.txt"))
	probed_domains_file = shlex.quote(str(outdir / "probed_domains.txt"))
	domains_403_file = shlex.quote(str(outdir / "403_domains.txt"))
	takeover_file = shlex.quote(str(outdir / "takeover.txt"))
	amass_subs_file = shlex.quote(str(outdir / "amass.txt"))
	gob1_file = shlex.quote(str(outdir / "gobuster1.txt"))
	gob2_file = shlex.quote(str(outdir / "gobuster2.txt"))
	subfinder_file = shlex.quote(str(outdir / "subfinder.txt"))
	assetfinder_file = shlex.quote(str(outdir / "assetfinder.txt"))
	findomain_file = shlex.quote(str(outdir / "findomain.txt"))
	qtarget = shlex.quote(target)

	"""
	Run the sequence of post-processing shell commands provided by the user,
	executed sequentially in the output directory.
	"""

	print("[+] Starting post-processing steps...")
    
	post_cmds = [
		# Extract IPs from amass
		f"grep -oE '[0-9]{1,3}(\\.[0-9]{1,3}){3}' {amass_subs_file} | awk '{{print $1}}' > {ip_file}",
		# Extract IPs from gobuster
		f"grep -oE '[0-9]{1,3}(\\.[0-9]{1,3}){3}' {gob1_file} >> {ip_file}",
		f"grep -oE '[0-9]{1,3}(\\.[0-9]{1,3}){3}' {gob2_file} >> {ip_file}",
		# Resolve PTRs and keep lines containing the target domain
		f"cat {ip_file} | sort -u | dnsx -ptr -resp-only | grep {qtarget} > {dnsx_file}",
		# Remove temporary ips file
		f"rm -f {ip_file}",
		# Collect unique subdomains from all txt outputs that end with the target
		f"cat *.txt 2>/dev/null | sort -u | grep -oE '[a-zA-Z0-9._-]+\\.{re.escape(target)}' > {live_subs_file}",
		# Probe with httpx-toolkit
		f"httpx-toolkit -l {live_subs_file} -title -sc -location -td -probe -silent -o {httpx_output_file}",
		# Filter httpx results: successful probes (exclude FAILED and 500)
		f"cat {httpx_output_file} | grep -v 'FAILED' | grep -v '500' | awk '{{print $1}}' | tee {probed_domains_file}",
		# Extract 403 responses
		f"cat {httpx_output_file} | grep -v 'FAILED' | grep '403' | awk '{{print $1}}' | tee {domains_403_file}",
		# Prepare takeover.txt by stripping protocol
		f"sed -E 's|^https?://||' {live_subs_file} >> {takeover_file}",
		# Cleanup requested files
		f"rm -f {amass_subs_file} {assetfinder_file} {findomain_file} {gob2_file} {gob1_file} {httpx_output_file} {subfinder_file} {live_subs_file} {dnsx_file}",
	]
	
	for cmd in post_cmds:
		print(f"[+] Running: {cmd}")
		try:
			res = subprocess.run(cmd, shell=True, cwd=str(outdir))
			if res.returncode == 0:
				print("    -> OK (exit 0)")
			else:
				print(f"    -> exited with code {res.returncode} (continuing)")
		except Exception as e:
			print(f"    -> Exception while running command: {e} (continuing)")

	print("[+] Post-processing finished.")


def main():
	parser = argparse.ArgumentParser(description="Parallel recon launcher for bug-bounty recon")
	parser.add_argument("target", help="Target domain (e.g. target.com)")
	parser.add_argument("-o", "--output", default=".", help="Output directory (default: current working directory)")
	parser.add_argument("-gwl1", "--gobuster-wordlist-1", default="/usr/share/seclists/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt", help="Worlist for first gobuster command (default: /usr/share/wordlists/seclists/Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt)")
	parser.add_argument("-gwl2", "--gobuster-wordlist-2", default="/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt", help="Worlist for second gobuster command (default: /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt)")
	args = parser.parse_args()

	target = args.target.strip()
	outdir = Path(args.output).expanduser().resolve()
	gobuster_wordlist_1 = args.gobuster_wordlist_1
	gobuster_wordlist_2 = args.gobuster_wordlist_2

	if not target:
		print("Invalid target.")
		sys.exit(2)

	# Verify required tools
	missing = check_tools()
	if missing:
		print("[-] Missing required tools. Exiting.")
		for m in missing:
			print(f"    - {m}")
		print("Please install the missing tools and rerun the script.")
		sys.exit(1)

	# Verify gobuster wordlists
	check_wordlists(gobuster_wordlist_1, gobuster_wordlist_2)

	# Create output dir if needed
	try:
		outdir.mkdir(parents=True, exist_ok=True)
	except Exception as e:
		print(f"[-] Failed to create or access output directory '{outdir}': {e}")
		sys.exit(1)

	# Check writable
	test_file = outdir / ".recon_write_test"
	try:
		test_file.write_text("ok")
		test_file.unlink()
	except Exception as e:
		print(f"[-] Output directory '{outdir}' is not writable: {e}")
		sys.exit(1)

	print(f"[+] Target: {target}")
	print(f"[+] Output directory: {outdir}")

	tasks = make_commands(target, outdir, gobuster_wordlist_1, gobuster_wordlist_2)

	# Launch all commands in parallel
	processes = {}
	for cmd, name in tasks:
		p = launch_shell_command(cmd, name)
		processes[name] = (cmd, p)

	# Wait for all to finish (no timeout)
	print("[+] All tools started. Waiting for processes to finish...")
	for name, (cmd, proc) in processes.items():
		try:
			ret = proc.wait()  # no timeout
		except KeyboardInterrupt:
			print("[!] KeyboardInterrupt received. Terminating child processes...")
			# attempt to terminate all child processes
			for n, (_, p) in processes.items():
				try:
					p.terminate()
				except Exception:
					pass
			# re-raise to exit
			raise
		if ret == 0:
			print(f"[+] {name} finished successfully (exit 0).")
		else:
			print(f"[-] {name} exited with code {ret}. (command: {cmd})")
			sys.exit(ret)

	print("[+] amass, gobuster, subfinder, assetfinder and findomain done.")

	run_post_processing(target, outdir)

	print("[+] Recon finished. Check the output files in:", outdir)
	print("[+] Done.")


if __name__ == "__main__":
	main()

