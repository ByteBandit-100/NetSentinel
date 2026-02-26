# engine/vuln/vuln_database.py

VULN_DB = [

    # ============================================================
    # SMB
    # ============================================================

    {
        "id": "CVE-2017-0144",
        "name": "EternalBlue SMB Remote Code Execution",
        "match": {
            "port": 445,
            "service": "SMB",
            "version_contains": ["SMBv1"]
        },
        "severity": "CRITICAL",
        "description": "SMBv1 vulnerability allowing remote code execution on unpatched Windows systems."
    },

    {
        "id": "CVE-2020-0796",
        "name": "SMBGhost Remote Code Execution",
        "match": {
            "port": 445,
            "service": "SMB",
            "version_contains": ["SMBv3"]
        },
        "severity": "CRITICAL",
        "description": "SMBv3 compression vulnerability affecting Windows 10 systems."
    },

    # ============================================================
    # RDP
    # ============================================================

    {
        "id": "CVE-2019-0708",
        "name": "BlueKeep RDP Remote Code Execution",
        "match": {
            "port": 3389,
            "service": "RDP",
            "version_contains": ["Windows 7", "Windows Server 2008"]
        },
        "severity": "CRITICAL",
        "description": "Pre-authentication RCE vulnerability in Remote Desktop Services."
    },

    # ============================================================
    # FTP
    # ============================================================

    {
        "id": "CVE-2011-2523",
        "name": "vsFTPd Backdoor Command Execution",
        "match": {
            "port": 21,
            "service": "FTP",
            "version_contains": ["vsFTPd 2.3.4"]
        },
        "severity": "CRITICAL",
        "description": "Backdoor vulnerability in vsFTPd 2.3.4 allowing command execution."
    },

    # ============================================================
    # SSH
    # ============================================================

    {
        "id": "CVE-2018-15473",
        "name": "OpenSSH Username Enumeration",
        "match": {
            "port": 22,
            "service": "SSH",
            "version_contains": ["OpenSSH 7."]
        },
        "severity": "MEDIUM",
        "description": "Allows remote attackers to enumerate valid usernames."
    },

    # ============================================================
    # HTTP / Apache
    # ============================================================

    {
        "id": "CVE-2021-41773",
        "name": "Apache Path Traversal",
        "match": {
            "port": 80,
            "service": "HTTP",
            "version_contains": ["Apache/2.4.49"]
        },
        "severity": "HIGH",
        "description": "Apache 2.4.49 path traversal vulnerability."
    },

    {
        "id": "CVE-2021-42013",
        "name": "Apache Path Traversal RCE",
        "match": {
            "port": 80,
            "service": "HTTP",
            "version_contains": ["Apache/2.4.50"]
        },
        "severity": "CRITICAL",
        "description": "Apache 2.4.50 path traversal leading to remote code execution."
    },

    # ============================================================
    # NGINX
    # ============================================================

    {
        "id": "CVE-2013-2028",
        "name": "Nginx Integer Overflow",
        "match": {
            "port": 80,
            "service": "HTTP",
            "version_contains": ["nginx/1.3.9"]
        },
        "severity": "HIGH",
        "description": "Integer overflow vulnerability in nginx 1.3.9."
    },

    # ============================================================
    # OpenSSL / HTTPS
    # ============================================================

    {
        "id": "CVE-2014-0160",
        "name": "OpenSSL Heartbleed",
        "match": {
            "port": 443,
            "service": "HTTPS",
            "version_contains": ["OpenSSL 1.0.1"]
        },
        "severity": "CRITICAL",
        "description": "Heartbleed vulnerability allowing memory disclosure."
    },

    # ============================================================
    # MySQL
    # ============================================================

    {
        "id": "CVE-2012-2122",
        "name": "MySQL Authentication Bypass",
        "match": {
            "port": 3306,
            "service": "MySQL",
            "version_contains": ["5.5"]
        },
        "severity": "CRITICAL",
        "description": "Authentication bypass vulnerability in MySQL 5.5."
    },

    # ============================================================
    # PostgreSQL
    # ============================================================

    {
        "id": "CVE-2018-1058",
        "name": "PostgreSQL Privilege Escalation",
        "match": {
            "port": 5432,
            "service": "PostgreSQL",
            "version_contains": ["10."]
        },
        "severity": "HIGH",
        "description": "Improper search path handling vulnerability."
    },

    # ============================================================
    # MongoDB
    # ============================================================

    {
        "id": "MONGO-UNAUTH-001",
        "name": "MongoDB Unauthenticated Access",
        "match": {
            "port": 27017,
            "service": "MongoDB"
        },
        "severity": "CRITICAL",
        "description": "MongoDB instance exposed without authentication."
    },

    # ============================================================
    # Redis
    # ============================================================

    {
        "id": "REDIS-UNAUTH-001",
        "name": "Redis Unauthenticated Access",
        "match": {
            "port": 6379,
            "service": "Redis"
        },
        "severity": "CRITICAL",
        "description": "Redis server exposed without authentication."
    },

    # ============================================================
    # DNS
    # ============================================================

    {
        "id": "CVE-2020-1350",
        "name": "Windows DNS Server RCE",
        "match": {
            "port": 53,
            "service": "DNS",
            "version_contains": ["Windows Server 2016"]
        },
        "severity": "CRITICAL",
        "description": "SigRed vulnerability in Windows DNS server."
    },

    # ============================================================
    # SNMP (UDP)
    # ============================================================

    {
        "id": "SNMP-PUBLIC-001",
        "name": "SNMP Public Community String",
        "match": {
            "port": 161,
            "service": "SNMP"
        },
        "severity": "HIGH",
        "description": "SNMP service using default 'public' community string."
    },

    # ============================================================
    # NTP (UDP)
    # ============================================================

    {
        "id": "CVE-2013-5211",
        "name": "NTP Amplification Vulnerability",
        "match": {
            "port": 123,
            "service": "NTP"
        },
        "severity": "HIGH",
        "description": "NTP monlist command amplification vulnerability."
    },

    # ============================================================
    # Docker API
    # ============================================================

    {
        "id": "DOCKER-API-001",
        "name": "Docker Remote API Exposed",
        "match": {
            "port": 2375,
            "service": "Docker"
        },
        "severity": "CRITICAL",
        "description": "Docker remote API exposed without TLS authentication."
    },

    # ============================================================
    # Kubernetes
    # ============================================================

    {
        "id": "K8S-API-001",
        "name": "Kubernetes API Server Exposed",
        "match": {
            "port": 6443,
            "service": "Kubernetes"
        },
        "severity": "CRITICAL",
        "description": "Kubernetes API server exposed publicly."
    },

]