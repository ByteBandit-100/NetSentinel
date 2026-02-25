VULN_DB = [
    {
        "id": "CVE-2017-0144",
        "name": "EternalBlue SMB Vulnerability",
        "port": 445,
        "service": "SMB",
        "version": "Windows 7",
        "keyword": "SMBv1",
        "severity": "CRITICAL"
    },
    {
        "id": "CVE-2014-0160",
        "name": "OpenSSL Heartbleed",
        "port": 443,
        "service": "HTTPS",
        "version": "OpenSSL 1.0.1",
        "keyword": "OpenSSL",
        "severity": "HIGH"
    },
    {
        "id": "CVE-2012-1823",
        "name": "PHP CGI Remote Code Execution",
        "port": 80,
        "service": "HTTP",
        "version": "PHP/5.3",
        "keyword": "PHP",
        "severity": "HIGH"
    },

    #udp
    {
        "id": "CVE-2013-5211",
        "name": "NTP Amplification Vulnerability",
        "service": "ntp",
        "port": 123,
        "keyword": "monlist",
        "severity": "HIGH"
    },
    {
        "id": "CVE-2015-5477",
        "name": "BIND DNS TKEY Query DoS",
        "service": "domain",
        "port": 53,
        "keyword": "bind",
        "severity": "MEDIUM"
    },
    {
        "id": "SNMP-PUBLIC-001",
        "name": "SNMP Public Community String",
        "service": "snmp",
        "port": 161,
        "keyword": "public",
        "severity": "HIGH"
    }
]
