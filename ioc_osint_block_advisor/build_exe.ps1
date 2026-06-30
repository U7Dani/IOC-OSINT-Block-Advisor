$ErrorActionPreference = "Stop"

pyinstaller --onefile --windowed --name IOC_OSINT_Block_Advisor --add-data "config;config" main.py
