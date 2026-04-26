import subprocess
import os
import re
import sys
import time

from modules import utils

# --- Platform-specific implementations ---

def _list_interfaces_linux():
    """Lists wireless interfaces on Linux."""
    interfaces = []
    try:
        # Using `iw dev` to list interfaces
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, check=True)
        # Example output:
        # phy#0
        #     Interface wlan0
        #         ifindex 3
        #         wdev 0x1
        #         addr ab:cd:ef:01:23:45
        #         ssid MyNetwork
        #         type managed
        #         channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
        #         txpower 20.00 dBm
        #
        # phy#1
        #     Interface wlan1mon
        #         ifindex 4
        #         wdev 0x2
        #         addr fe:dc:ba:98:76:54
        #         type monitor
        #         channel 1 (2412 MHz), width: 20 MHz, center1: 2412 MHz
        #         txpower 20.00 dBm

        current_interface = None
        for line in result.stdout.splitlines():
            if 'Interface' in line:
                match = re.search(r'Interface\s+(\S+)', line)
                if match:
                    current_interface = match.group(1)
                    interfaces.append({'name': current_interface, 'type': 'unknown', 'mac': ''})
            elif 'type' in line and current_interface:
                match = re.search(r'type\s+(\S+)', line)
                if match:
                    # Update the type for the last added interface
                    for iface in interfaces:
                        if iface['name'] == current_interface:
                            iface['type'] = match.group(1)
                            break
            elif 'addr' in line and current_interface:
                match = re.search(r'addr\s+([0-9a-fA-F:]+)', line)
                if match:
                    # Update the mac for the last added interface
                    for iface in interfaces:
                        if iface['name'] == current_interface:
                            iface['mac'] = match.group(1)
                            break

    except FileNotFoundError:
        log_message('!', "Error: 'iw' command not found. Please install `iw` (e.g., `sudo apt install iw`).")
    except subprocess.CalledProcessError as e:
        log_message('!', f"Error running 'iw dev': {e.stderr.strip()}")
    except Exception as e:
        log_message('!', f"An unexpected error occurred while listing interfaces: {e}")
    return interfaces

def _enable_monitor_mode_linux(interface):
    """Enables monitor mode for a given interface on Linux."""
    try:
        # Check if airmon-ng is available, if not, try iw
        try:
            subprocess.run(['which', 'airmon-ng'], check=True, capture_output=True)
            log_message('*', f"Using airmon-ng to enable monitor mode on {interface}...")
            # airmon-ng usually renames the interface, so we need to capture the new name
            result = subprocess.run(['sudo', 'airmon-ng', 'start', interface], capture_output=True, text=True, check=True)
            log_message('+', f"airmon-ng output:\n{result.stdout.strip()}")
            
            # airmon-ng often creates a new interface like wlan0mon
            match = re.search(r'\(monitor mode enabled on\s+(\S+)\)', result.stdout)
            if match:
                monitor_interface = match.group(1)
                log_message('+', f"Monitor mode enabled on new interface: {monitor_interface}")
                return True, monitor_interface
            else:
                log_message('!', "Could not determine new monitor interface name from airmon-ng output. Please check manually.")
                return False, None
        except (FileNotFoundError, subprocess.CalledProcessError):
            log_message('*', "airmon-ng not found or failed. Attempting with `iw` commands...")
            # Bring interface down
            subprocess.run(['sudo', 'ifconfig', interface, 'down'], capture_output=True, text=True, check=True)
            # Set type to monitor
            subprocess.run(['sudo', 'iw', interface, 'set', 'type', 'monitor'], capture_output=True, text=True, check=True)
            # Bring interface up
            subprocess.run(['sudo', 'ifconfig', interface, 'up'], capture_output=True, text=True, check=True)
            log_message('+', f"Monitor mode enabled on {interface} using `iw` commands.")
            return True, interface
    except FileNotFoundError:
        log_message('!', "Error: Required commands (airmon-ng, iw, ifconfig) not found. Please install aircrack-ng suite and net-tools.")
        return False, None
    except subprocess.CalledProcessError as e:
        log_message('!', f"Error enabling monitor mode on {interface}: {e.stderr.strip()}")
        log_message('!', "Ensure you have proper permissions (run as root/sudo).")
        return False, None
    except Exception as e:
        log_message('!', f"An unexpected error occurred while enabling monitor mode: {e}")
        return False, None

def _disable_monitor_mode_linux(interface):
    """Disables monitor mode for a given interface on Linux."""
    try:
        # Try to stop airmon-ng if it was used
        try:
            subprocess.run(['which', 'airmon-ng'], check=True, capture_output=True)
            log_message('*', f"Using airmon-ng to stop monitor mode on {interface}...")
            result = subprocess.run(['sudo', 'airmon-ng', 'stop', interface], capture_output=True, text=True, check=True)
            log_message('+', f"airmon-ng output:\n{result.stdout.strip()}")
            
            # airmon-ng stop might revert the interface to its original name (e.g., wlan0 from wlan0mon)
            # We don't necessarily need to return the new name here, just confirm success
            log_message('+', f"Monitor mode disabled on {interface}.")
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            log_message('*', "airmon-ng not found or failed. Attempting with `iw` commands...")
            # Bring interface down
            subprocess.run(['sudo', 'ifconfig', interface, 'down'], capture_output=True, text=True, check=True)
            # Set type to managed
            subprocess.run(['sudo', 'iw', interface, 'set', 'type', 'managed'], capture_output=True, text=True, check=True)
            # Bring interface up
            subprocess.run(['sudo', 'ifconfig', interface, 'up'], capture_output=True, text=True, check=True)
            log_message('+', f"Monitor mode disabled on {interface} using `iw` commands.")
            return True
    except FileNotFoundError:
        log_message('!', "Error: Required commands (airmon-ng, iw, ifconfig) not found. Please install aircrack-ng suite and net-tools.")
        return False
    except subprocess.CalledProcessError as e:
        log_message('!', f"Error disabling monitor mode on {interface}: {e.stderr.strip()}")
        log_message('!', "Ensure you have proper permissions (run as root/sudo).")
        return False
    except Exception as e:
        log_message('!', f"An unexpected error occurred while disabling monitor mode: {e}")
        return False

def _scan_networks_linux(interface, duration=10, output_file='scan_output.csv'):
    """Scans for Wi-Fi networks using airodump-ng on Linux."""
    # Ensure airodump-ng is available
    try:
        subprocess.run(['which', 'airodump-ng'], check=True, capture_output=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        log_message('!', "Error: 'airodump-ng' command not found. Please install aircrack-ng suite.")
        return []

    if not os.path.exists('outputs'):
        os.makedirs('outputs')

    full_output_path = os.path.join('outputs', output_file)

    log_message('*', f"Starting network scan on {interface} for {duration} seconds. Output to {full_output_path} (temporary CSV).")
    log_message('*', "Note: airodump-ng must run on an interface already in monitor mode.")
    
    # airodump-ng writes multiple files (e.g., .cap, .csv, .kismet.csv, .log)
    # We'll use --output-format csv to get a CSV we can parse
    # --write to specify base name for output files
    base_output_name = os.path.splitext(full_output_path)[0]
    
    command = ['sudo', 'airodump-ng', '--output-format', 'csv', '--write', base_output_name, interface]
    process = None
    networks = []

    try:
        # Start airodump-ng in the background
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Give airodump-ng some time to collect data
        time.sleep(duration)
        
        # Terminate airodump-ng
        process.terminate()
        process.wait(timeout=5)

        # Find the actual CSV file generated (it appends -01.csv, -02.csv etc.)
        generated_csv_file = None
        for f_name in os.listdir('outputs'):
            if f_name.startswith(os.path.basename(base_output_name)) and f_name.endswith('.csv'):
                generated_csv_file = os.path.join('outputs', f_name)
                break
        
        if generated_csv_file and os.path.exists(generated_csv_file):
            log_message('+', f"Parsing scan results from {generated_csv_file}")
            with open(generated_csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Split the content by "Station MAC" to separate APs from clients
                sections = content.split("Station MAC")
                if len(sections) > 0:
                    ap_section = sections[0].strip()
                    # Parse APs (BSSID, First time seen, Last time seen, Channel, Speed, Privacy, Cipher, Authentication, Power, #beacons, #data, #/s, Kismet, ESSID, Latitude, Longitude, Altitude, Freqency)
                    ap_lines = ap_section.splitlines()
                    if ap_lines:
                        # Skip header line, or try to find it dynamically
                        # Assuming header is the first line, and actual data starts after it
                        headers = [h.strip() for h in ap_lines[0].split(',')]
                        for line in ap_lines[1:]:
                            if not line.strip():
                                continue
                            parts = [p.strip() for p in line.split(',')]
                            if len(parts) >= len(headers): # Ensure enough parts to match headers
                                ap_data = dict(zip(headers, parts))
                                networks.append({
                                    'bssid': ap_data.get('BSSID'),
                                    'essid': ap_data.get('ESSID'),
                                    'channel': ap_data.get('Channel'),
                                    'privacy': ap_data.get('Privacy'),
                                    'cipher': ap_data.get('Cipher'),
                                    'auth': ap_data.get('Authentication'),
                                    'power': ap_data.get('Power'),
                                    'type': 'AP'
                                })
            # Clean up temporary CSV files
            for f_name in os.listdir('outputs'):
                if f_name.startswith(os.path.basename(base_output_name)):
                    os.remove(os.path.join('outputs', f_name))
        else:
            log_message('!', "No CSV file generated by airodump-ng.")

    except subprocess.CalledProcessError as e:
        log_message('!', f"Error running airodump-ng: {e.stderr.strip()}")
        log_message('!', "Ensure you have proper permissions (run as root/sudo).")
    except Exception as e:
        log_message('!', f"An unexpected error occurred during network scan: {e}")
    finally:
        if process and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
    
    return networks

# --- Cross-platform dispatch ---

def list_interfaces():
    """Lists available wireless interfaces based on the operating system."""
    if sys.platform.startswith('linux'):
        return _list_interfaces_linux()
    else:
        log_message('!', f"Wireless interface listing not supported on {sys.platform} yet.")
        return []

def enable_monitor_mode(interface):
    """Enables monitor mode for the given interface."""
    if sys.platform.startswith('linux'):
        return _enable_monitor_mode_linux(interface)
    else:
        log_message('!', f"Enabling monitor mode not supported on {sys.platform} yet.")
        return False, None

def disable_monitor_mode(interface):
    """Disables monitor mode for the given interface."""
    if sys.platform.startswith('linux'):
        return _disable_monitor_mode_linux(interface)
    else:
        log_message('!', f"Disabling monitor mode not supported on {sys.platform} yet.")
        return False

def scan_networks(interface, duration=10):
    """Scans for Wi-Fi networks."""
    if sys.platform.startswith('linux'):
        return _scan_networks_linux(interface, duration)
    else:
        log_message('!', f"Network scanning not supported on {sys.platform} yet.")
        return []

# Placeholder for other functions as per the plan
def capture_packets(interface, bssid=None, channel=None, duration=None, output_file='capture.cap'):
    """Placeholder for packet capture."""
    log_message('!', f"Packet capture not implemented yet on {sys.platform}.")
    return False

def deauthenticate_client(interface, client_mac, ap_mac, count=1):
    """Placeholder for deauthentication attack."""
    log_message('!', f"Deauthentication attack not implemented yet on {sys.platform}.")
    return False

def crack_wpa(cap_file, wordlist):
    """Placeholder for WPA/WPA2 cracking."""
    log_message('!', f"WPA/WPA2 cracking not implemented yet on {sys.platform}.")
    return False

if __name__ == '__main__':
    # Example usage for testing
    print("Listing interfaces:")
    interfaces = list_interfaces()
    for iface in interfaces:
        print(f"  - {iface['name']} ({iface['type']}) MAC: {iface['mac']}")

    # This part requires actual hardware and root privileges
    # if sys.platform.startswith('linux'):
    #     if interfaces:

    #         success, mon_iface = enable_monitor_mode(test_interface)
    #         if success and mon_iface:
    #             print(f"\nScanning networks on {mon_iface}...")
    #             networks = scan_networks(mon_iface, duration=15)
    #             print("\nDiscovered Networks:")    #             for net in networks:
    #                 print(f"  ESSID: {net.get('essid', 'N/A')}, BSSID: {net.get('bssid', 'N/A')}, Channel: {net.get('channel', 'N/A')}, Privacy: {net.get('privacy', 'N/A')}")
    #             
    # 
    #             disable_monitor_mode(mon_iface)
    #         else:
    #             print("Failed to enable monitor mode.")
    #     else:
    #         print("No wireless interfaces found for testing monitor mode/scanning.")
