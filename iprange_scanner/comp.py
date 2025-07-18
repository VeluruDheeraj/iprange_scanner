import socket
from requests import get
import tkinter as tk
from tkinter import scrolledtext, messagebox
from tkinter.ttk import Progressbar
import threading
import csv

def isOpen(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((ip, int(port)))
        s.shutdown(socket.SHUT_RDWR)
        return True
    except:
        return False
    finally:
        s.close()

def ipRange(start_ip, end_ip):
    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start[:]
    ip_range = []

    ip_range.append(start_ip)
    while temp != end:
        temp[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i-1] += 1
        ip_range.append(".".join(map(str, temp)))

    return ip_range

def parse_ports(port_input):
    ports = set()
    parts = port_input.split(",")
    for part in parts:
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part.strip()))
    return sorted(ports)

def scan_ips():
    start_ip = start_ip_entry.get()
    end_ip = end_ip_entry.get()
    port_input = port_entry.get()

    if not start_ip or not end_ip or not port_input:
        messagebox.showerror("Input error", "Please enter start IP, end IP, and ports")
        return

    try:
        ports = parse_ports(port_input)
    except ValueError:
        messagebox.showerror("Input error", "Ports must be integers, ranges, or comma-separated")
        return

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Scanning {start_ip} to {end_ip} on ports {ports}\n")

    results = []

    ips = ipRange(start_ip, end_ip)
    total_tasks = len(ips) * len(ports)
    progress["maximum"] = total_tasks
    progress["value"] = 0

    task_count = 0

    for ip in ips:
        ip_has_open_port = False

        for port in ports:
            if isOpen(ip, port):
                ip_has_open_port = True
                output_text.insert(tk.END, f"{ip}:{port} is open\n")
                output_text.see(tk.END)
                result = [ip, port, "open"]

                # Try to fetch web banner if HTTP/HTTPS
                if port in [80, 443]:
                    try:
                        url = ("https://" if port == 443 else "http://") + ip
                        response = get(url, timeout=3)
                        html_preview = response.text[:200].replace('\n', ' ').strip()
                        output_text.insert(tk.END, f"Device info: {html_preview}...\n")
                        output_text.see(tk.END)
                        result.append(html_preview)
                    except Exception as e:
                        output_text.insert(tk.END, f"Failed to get HTML from {ip}:{port} - {str(e)}\n")
                        result.append("Failed to retrieve HTML")
                else:
                    result.append("")
                results.append(result)
            else:
                results.append([ip, port, "closed", ""])

            task_count += 1
            progress["value"] = task_count
            progress.update()

    # Save to CSV
    with open("scan_results.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Port", "Status", "Banner/Info"])
        writer.writerows(results)

    # Save open/closed IP:Port to text files
    with open("up_ips.txt", "w") as f_up, open("down_ips.txt", "w") as f_down:
        for row in results:
            ip, port, status, _ = row
            if status == "open":
                f_up.write(f"{ip}:{port}\n")
            elif status == "closed":
                f_down.write(f"{ip}:{port}\n")

    output_text.insert(tk.END, "\nScan complete.\n")
    output_text.insert(tk.END, "Saved: scan_results.csv, up_ips.txt, down_ips.txt\n")
    output_text.see(tk.END)

def start_scan_thread():
    scan_thread = threading.Thread(target=scan_ips)
    scan_thread.daemon = True
    scan_thread.start()

# GUI Setup
root = tk.Tk()
root.title("Enhanced Port Scanner")

tk.Label(root, text="Start IP:").grid(row=0, column=0, sticky="e")
start_ip_entry = tk.Entry(root, width=20)
start_ip_entry.grid(row=0, column=1)

tk.Label(root, text="End IP:").grid(row=1, column=0, sticky="e")
end_ip_entry = tk.Entry(root, width=20)
end_ip_entry.grid(row=1, column=1)

tk.Label(root, text="Port(s):").grid(row=2, column=0, sticky="e")
port_entry = tk.Entry(root, width=20)
port_entry.insert(0, "80,443")  # default ports
port_entry.grid(row=2, column=1)

scan_button = tk.Button(root, text="Start Scan", command=start_scan_thread)
scan_button.grid(row=3, column=0, columnspan=2, pady=5)

progress = Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress.grid(row=4, column=0, columnspan=2, pady=5)

output_text = scrolledtext.ScrolledText(root, width=70, height=20)
output_text.grid(row=5, column=0, columnspan=2, pady=10)

root.mainloop()
