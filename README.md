# subenum

This script automates the process of subdomains enumaration using several existing tools (amass, gobuster, subfinder, assetfinder)


### 🛠️ What This Tool Does:
- ✅ Run subdomain enumeration tools with subprocess
- ✅ Checks live subdomains

This makes subdomain enumeration faster, and more effective! 🚀


### Prerequisites
Ensure the following tools are installed before running the script:

- [amass](https://github.com/owasp-amass/amass)
- [gobuster](https://github.com/OJ/gobuster)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [httpx-toolkit](https://github.com/projectdiscovery/httpx)
- [docker](https://docs.docker.com/engine/install/)
- [dnsx](https://github.com/projectdiscovery/dnsx)

or if you use docker 7Gb of storage

### Installation
Clone the repository and navigate into it:
```
git clone https://github.com/havard-ludovic/subenum.git
cd subenum
```

### Usage
```
python3 subenum.py target.com
python3 subenum.py target.com -o /path/to/output/directory
```

with docker
```
docker build -t subenum .
docker run -it --entrypoint /bin/bash subenum
python3 subenum.py target.com
```


### Output Files
- ```probed_domains.txt``` : list of live subdomains
- ```403_domains.txt``` : list of subdomains that return 403 http code
- ```takeover.txt``` : same list than probed_domains.txt without http:// or https://


### Disclamer
This tool is intended for educational and legal security testing purposes only. The author is not responsible for any misuse of this script.
