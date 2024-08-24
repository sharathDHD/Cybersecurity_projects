# Network Scanner Application

Welcome to the Network Scanner Application! This tool is designed to perform comprehensive scans on network targets, identifying open ports, running services, and potential vulnerabilities. Built with Python, utilizing libraries such as `nmap`, `streamlit`, and `logging`, this application provides a user-friendly interface for network scanning operations.

## Features

- **Network Scanning**: Scan IP addresses or entire network ranges to discover open ports and services running on those ports.
- **Vulnerability Detection**: Enable vulnerability scanning to identify potential security risks associated with open ports and services.
- **Interactive UI**: Utilizes Streamlit for an interactive web-based interface, allowing users to easily input targets, select scanning options, and view scan results.
- **Logging**: Detailed logging of scan operations and errors for troubleshooting and audit purposes.
- **Results Export**: Save scan results to a JSON file for further analysis or reporting.

## Getting Started

To use the Network Scanner Application, follow these steps:

1. **Installation**: Ensure you have Python installed on your system. Install the required libraries by running `pip install nmap streamlit`.

2. **Running the Application**: Navigate to the directory containing the application script and run `streamlit run app.py` in your terminal. This will start the Streamlit server and open the application in your default web browser.

3. **Using the Application**:
   - Enter the target IP address or network range in the "Enter the target IP address or network range" input field.
   - Specify the port range to scan in the "Enter the port range to scan" input field. By default, it scans ports 1 through 1024.
   - Check the "Enable vulnerability scanning" checkbox if you want to perform a vulnerability scan in addition to the standard network scan.
   - Click the "Scan" button to initiate the scan.

## Scan Results

Once the scan is completed, the results will be displayed in the application interface. You can view details about each host, including open ports, service names, and detected vulnerabilities (if vulnerability scanning was enabled).

To save the scan results for future reference or further analysis, click the "Save Results" button. The results will be saved in a JSON file named `scan_results_YYYYMMDD_HHMMSS.json`, where `YYYYMMDD_HHMMSS` represents the current date and time.

## Logging

The application logs scan progress, warnings, and errors using Python's built-in logging module. Logs are displayed in the console and can be useful for troubleshooting issues during scans.

## Contributing

Contributions to the Network Scanner Application are welcome! Whether it's adding new features, improving existing functionality, or fixing bugs, your contributions can help enhance this tool. Please follow the standard fork-and-pull request workflow.
