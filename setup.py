from setuptools import setup , find_packages
setup (
    name = "NetworkScanner" ,
    version = "0.1.0" ,
    author = "Ayush Kumar Jha ",
    packages = find_packages() ,
    install_requires = [
        "scapy==2.7.0",
        "ipaddress==1.0.23",
        "typing-extensions==4.5.0",
        "windows-curses==2.4.1; platform_system == 'Windows'",
    ],
    
)