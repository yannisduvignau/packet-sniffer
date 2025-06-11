#  Packet sniffer

### 1. Create a Python virtual environment (using Python 3)
```bash
    python3 -m venv env
```

### 2. Activate the virtual environment
```bash
    source env/bin/activate
```

### 3. Prepare the requirements file and install dependencies
```bash
    echo "scapy" > requirements.txt
    pip install -r ./requirements.txt
```

### 4. Create a .gitignore file to avoid committing sensitive files
```bash
    echo ".gitignore\nenv/\nrequirements.txt\n.env*\n*.log\n*.pcap" > .gitignore
```

### 5. Run the sniffer
```bash
    python3 main.py
```

### 6. Deactivate the virtual environment
```bash
    deactivate
```