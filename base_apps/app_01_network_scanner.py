import nmap
import streamlit as st
import logging
import json
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

def scan_network(target, ports):
    nm = nmap.PortScanner()
    try:
        logger.info(f"Scanning {target} for open ports and services on ports {ports}...")
        nm.scan(target, ports)
        
        if not nm.all_hosts():
            logger.warning(f"No hosts found for target {target}.")
            return

        results = []
        for host in nm.all_hosts():
            host_info = {
                "Host": host,
                "Hostname": nm[host].hostname(),
                "State": nm[host].state(),
                "Protocols": []
            }
            
            for proto in nm[host].all_protocols():
                protocol_info = {"Protocol": proto, "Ports": []}
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    protocol_info["Ports"].append({
                        "Port": port,
                        "State": nm[host][proto][port]['state'],
                        "Service": nm[host][proto][port]['name']
                    })
                host_info["Protocols"].append(protocol_info)
            results.append(host_info)
        return results
    except nmap.PortScannerError as e:
        logger.error(f"PortScannerError: {str(e)}")
        st.error(f"PortScannerError: {str(e)}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
        st.error(f"An unexpected error occurred: {str(e)}")

def scan_vulnerabilities(target):
    nm = nmap.PortScanner()
    try:
        logger.info(f"Scanning {target} for vulnerabilities...")
        nm.scan(target, arguments='--script vuln')

        if not nm.all_hosts():
            logger.warning(f"No hosts found for target {target}.")
            return

        results = []
        for host in nm.all_hosts():
            host_info = {
                "Host": host,
                "Hostname": nm[host].hostname(),
                "State": nm[host].state(),
                "Protocols": []
            }
            
            for proto in nm[host].all_protocols():
                protocol_info = {"Protocol": proto, "Ports": []}
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    port_info = {
                        "Port": port,
                        "State": nm[host][proto][port]['state'],
                        "Service": nm[host][proto][port]['name'],
                        "Vulnerabilities": []
                    }
                    if 'script' in nm[host][proto][port]:
                        for script in nm[host][proto][port]['script']:
                            port_info["Vulnerabilities"].append({
                                "Script": script,
                                "Details": nm[host][proto][port]['script'][script]
                            })
                    protocol_info["Ports"].append(port_info)
                host_info["Protocols"].append(protocol_info)
            results.append(host_info)
        return results
    except nmap.PortScannerError as e:
        logger.error(f"PortScannerError: {str(e)}")
        st.error(f"PortScannerError: {str(e)}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
        st.error(f"An unexpected error occurred: {str(e)}")

def save_results(results, filename):
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    st.success(f"Results saved to {filename}")

st.title("Network Scanner")

target = st.text_input("Enter the target IP address or network range (e.g., 192.168.1.0/24):")
ports = st.text_input("Enter the port range to scan (default: 1-1024):", "1-1024")
vuln_scan = st.checkbox("Enable vulnerability scanning")

if st.button("Scan"):
    if target:
        st.info("Starting the scan...")
        progress_bar = st.progress(0)
        total_steps = 2 if vuln_scan else 1
        progress_step = 0

        if vuln_scan:
            results = scan_vulnerabilities(target)
        else:
            results = scan_network(target, ports)

        progress_step += 1
        progress_bar.progress(progress_step / total_steps)
        
        if results:
            for host_info in results:
                st.subheader(f"Host: {host_info['Host']} ({host_info['Hostname']})")
                st.text(f"State: {host_info['State']}")
                for proto in host_info['Protocols']:
                    st.text(f"Protocol: {proto['Protocol']}")
                    for port_info in proto['Ports']:
                        st.text(f"Port: {port_info['Port']} - State: {port_info['State']} - Service: {port_info['Service']}")
                        if 'Vulnerabilities' in port_info and port_info['Vulnerabilities']:
                            for vuln in port_info['Vulnerabilities']:
                                st.text(f"Vulnerability: {vuln['Script']}\nDetails: {vuln['Details']}")
            
            progress_step += 1
            progress_bar.progress(progress_step / total_steps)

            # Save results button
            if st.button("Save Results"):
                filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                save_results(results, filename)
    else:
        st.warning("Please enter a target IP address or network range.")
