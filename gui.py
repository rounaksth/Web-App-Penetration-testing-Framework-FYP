import threading
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from Settings import SettingsWindow
from fpdf import FPDF
import subprocess
import os
import queue
from datetime import datetime
import logging
import signal
import time 
from tkinter import simpledialog
import json
from tkinter import scrolledtext
import webbrowser

# Global variable to track the running process
running_process = None
nmap_process = None
subjack_process = None
process_lock = threading.Lock()  # Lock for synchronizing access to running_process and nmap_process

# Configure logging
logging.basicConfig(filename="app.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Function to open settings
def open_settings():
    SettingsWindow(root)

# Function to open help
def open_help():
    messagebox.showinfo("Help", "This is the Help section for the framework.")

# Function to export scan results to a PDF
def export_to_pdf():
    # Find the latest output file for SQLi or XSS
    output_file = None
    scan_type = scan_type_var.get()
    prefix = "output_sqli" if scan_type == "SQLi" else "output_xss" if scan_type == "XSS" else "output_simple_xss" if scan_type == "Simple XSS" else None

    if prefix:
        output_files = [f for f in os.listdir() if f.startswith(prefix) and f.endswith(".txt")]
        if output_files:
            output_file = max(output_files, key=os.path.getctime)  # Get the latest file
        else:
            messagebox.showwarning("Export Failed", f"No {scan_type} scan results available.")
            return
    else:
        messagebox.showwarning("Export Failed", "Unsupported scan type for PDF export.")
        return

    with open(output_file, "r") as f:
        content = f.read()

    # Initialize PDF
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Set font for title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "SQL Injection Scan Report", ln=True, align="C")
    pdf.ln(10)

    # Parse and format content
    lines = content.splitlines()
    in_table = False
    table_data = []
    current_database = ""

    for i, line in enumerate(lines):
        # Header section
        if line.startswith("==="):
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, line.strip("=").strip(), ln=True)
        elif line.startswith("Target:") or line.startswith("Started at:") or line.startswith("Ended at:"):
            pdf.set_font("Arial", size=10)
            pdf.cell(0, 8, line, ln=True)
        elif ("SQL Injection" in line or "Cross-Site Scripting" in line or "DOM-based XSS" in line) and "|" in line:  # Structured result
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "Scan Summary", ln=True)
            pdf.set_font("Arial", size=10)
            vuln, severity, action = line.split("|")
            pdf.cell(0, 8, f"Vulnerability: {vuln}", ln=True)
            pdf.cell(0, 8, f"Severity: {severity}", ln=True)
            pdf.cell(0, 8, f"Action: {action}", ln=True)
            pdf.ln(5)

        elif scan_type == "XSS":
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "XSS Scan Details", ln=True)
            pdf.set_font("Arial", size=10)
            for line in lines:
                if "Payload:" in line:
                    pdf.multi_cell(0, 8, "Payload: " + line.strip())
                elif "Efficiency:" in line:
                    pdf.multi_cell(0, 8, "Efficiency: " + line.strip())
                elif "Vulnerable webpage" in line:
                    pdf.multi_cell(0, 8, "Vulnerable: " + line.strip())
                elif "DOM XSS" in line:
                    pdf.multi_cell(0, 8, "DOM XSS: " + line.strip())
                elif "WAF detected" in line:
                    pdf.multi_cell(0, 8, "WAF Info: " + line.strip())
            pdf.ln(5)

        # SQLMap banner
        elif line.startswith("        ___"):
            pdf.set_font("Courier", size=10)
            pdf.multi_cell(0, 5, "SQLMap Banner:\n" + line + "\n" + "\n".join(lines[i+1:i+5]))
            pdf.ln(5)

        # Database info
        elif line.startswith("web server operating system:") or line.startswith("web application technology:") or line.startswith("back-end DBMS:"):
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "System Information", ln=True)
            pdf.set_font("Arial", size=10)
            pdf.cell(0, 8, line, ln=True)
        # Database names
        elif line.startswith("available databases"):
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "Available Databases", ln=True)
            pdf.set_font("Arial", size=10)
            for db_line in lines[i+1:]:
                if db_line.startswith("[*]"):
                    pdf.cell(0, 8, db_line[3:].strip(), ln=True)
                elif not db_line.strip():
                    break
            pdf.ln(5)
        # Table enumeration
        elif line.startswith("Database:"):
            current_database = line.split("Database:")[1].strip()
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, f"Database: {current_database}", ln=True)
        elif line.startswith("[") and "tables]" in line:
            pdf.set_font("Arial", size=10)
            for table_line in lines[i+2:]:
                if table_line.startswith("|") and not table_line.startswith("+"):
                    pdf.cell(0, 8, table_line.strip("| ").strip(), ln=True)
                elif table_line.startswith("+"):
                    break
            pdf.ln(5)
        # Table columns and data
        elif line.startswith("Table:"):
            table_name = line.split("Table:")[1].strip()
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, f"Table: {table_name}", ln=True)
        elif line.startswith("[") and "columns]" in line:
            pdf.set_font("Arial", "B", 10)
            pdf.cell(40, 8, "Column", border=1)
            pdf.cell(40, 8, "Type", border=1)
            pdf.ln()
            pdf.set_font("Arial", size=10)
            for col_line in lines[i+2:]:
                if col_line.startswith("|") and not col_line.startswith("+"):
                    cols = [col.strip() for col in col_line.split("|")[1:-1]]
                    pdf.cell(40, 8, cols[0], border=1)
                    pdf.cell(40, 8, cols[1], border=1)
                    pdf.ln()
                elif col_line.startswith("+"):
                    break
            pdf.ln(5)
        elif line.startswith("[") and "entries]" in line:
            in_table = True
            table_data = []
            # Look for the header row immediately after "[X entries]"
            next_line_idx = i + 1
            if next_line_idx < len(lines) and lines[next_line_idx].startswith("+"):
                header_idx = next_line_idx + 1
                if header_idx < len(lines) and lines[header_idx].startswith("|"):
                    table_data.append([col.strip() for col in lines[header_idx].split("|")[1:-1]])
        elif in_table and line.startswith("|") and not line.startswith("+"):
            table_data.append([col.strip() for col in line.split("|")[1:-1]])
        elif in_table and line.startswith("+"):
            in_table = False
            if table_data and len(table_data) > 0 and len(table_data[0]) > 0:  # Ensure table_data has content
                pdf.set_font("Arial", "B", 10)
                col_widths = [min(max(len(row[i]) for row in table_data) * 4, 60) for i in range(len(table_data[0]))]
                for col, width in zip(table_data[0], col_widths):
                    pdf.cell(width, 8, col, border=1)
                pdf.ln()
                pdf.set_font("Arial", size=10)
                for row in table_data[1:]:
                    for col, width in zip(row, col_widths):
                        pdf.cell(width, 8, col[:int(width/4)] if len(col) > int(width/4) else col, border=1)
                    pdf.ln()
                pdf.ln(5)
            else:
                pdf.set_font("Arial", size=10)
                pdf.cell(0, 8, "No data available for this table.", ln=True)
                pdf.ln(5)

    # Save PDF with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_filename = f"{scan_type.lower()}_scan_results_{timestamp}.pdf"
    pdf_file = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF Files", "*.pdf")],
        initialfile=default_filename
    )
    if pdf_file:
        pdf.output(pdf_file)
        messagebox.showinfo("Export Successful", f"Results exported to {pdf_file}")

# Function to show copyright
def show_copyright():
    messagebox.showinfo("Copyright", "© 2025 Rounak Pradhan. All Rights Reserved.")

# Function to contact support
def contact_support():
    messagebox.showinfo("Contact Support", "Email: rounakpradhan4@gmail.com\nPhone: +977-98078654567")

# Function to start penetration testing
def start_testing():
    global running_process, nmap_process  # Declare running_process as global

    target_url = url_entry.get().strip()
    scan_type = scan_type_var.get()
    scan_depth = depth_spinbox.get()
    timeout = timeout_spinbox.get()

    if not target_url or target_url == "Enter target URL here":
        messagebox.showerror("Error", "Please enter a valid target URL.")
        return

    script_path = "./pentest.sh"
    if not os.path.exists(script_path) or not os.access(script_path, os.X_OK):
        messagebox.showerror("Error", "Backend script not found or not executable.")
        return

    # Construct command to run the script within the virtual environment
    command = [script_path, target_url, scan_type, scan_depth, timeout, ""]

    # Clear previous results
    result_table.delete(*result_table.get_children())
    result_textbox.delete("1.0", tk.END) # Clear the output

    # Disable the "Start Scan" button and enable the "Stop Scan" button
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

    progress_bar.start()

    try:
        # Start the process
        with process_lock:
            running_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            nmap_process = running_process # Assign running_process to nmap_process

        # Wait for the PID file to be created
        pid_file = "pentest.pid"
        start_time = time.time()
        while not os.path.exists(pid_file) and (time.time() - start_time) < 5:  # Wait up to 5 seconds
            time.sleep(0.1)

        if not os.path.exists(pid_file):
            messagebox.showerror("Error", "Failed to start the scan. PID file not created.")
            progress_bar.stop()
            start_button.config(state=tk.NORMAL)
            stop_button.config(state=tk.DISABLED)
            return

        def read_output():
            global running_process, nmap_process  
            output_file_prefix = "output_sqli" if scan_type == "SQLi" else "output_xss" if scan_type == "XSS" else "output_simple_xss" if scan_type == "Simple XSS" else None
            output_file = None

            if output_file_prefix:
                # Read real-time output from stdout while the scan is running
                for line in iter(running_process.stdout.readline, ''):
                    if line:
                        output_queue.put(line.strip())
                    time.sleep(0.1)
                running_process.stdout.close()
                running_process.wait()

                # After the scan completes, look for the output file
                output_files = [f for f in os.listdir() if f.startswith(output_file_prefix) and f.endswith(".txt")]
                logging.info(f"Found output files: {output_files}")
                # Filter for files with timestamps 
                timestamped_files = [f for f in output_files if f.startswith(output_file_prefix + "_") and f[len(output_file_prefix) + 1:-4].isdigit()]
                if timestamped_files:
                    output_file = max(timestamped_files, key=lambda x: int(x.split("_")[-1].split(".")[0]))
                    logging.info(f"Selected timestamped output file: {output_file}")
                # Fallback to non-timestamped file (e.g., output_sqli.txt)
                elif output_file_prefix + ".txt" in output_files:
                    output_file = output_file_prefix + ".txt"
                    logging.info(f"Selected non-timestamped output file: {output_file}")
                else:
                    output_queue.put("No output file found.")
                    logging.warning("No output file found after scan completion.")

                # If an output file was found, process it
                if output_file and os.path.exists(output_file):
                    # Parse the file to populate the exploit listbox
                    with open(output_file, "r") as f:
                        lines = f.readlines()
                        logging.info(f"Reading output file contents:\n{''.join(lines)}")
                        for i, line in enumerate(lines):
                            if line.startswith("URL:"):
                                url = line.split("URL: ")[1].strip()
                                logging.info(f"Found URL: {url}")
                                next_line = lines[i + 2] if i + 2 < len(lines) else ""
                                logging.info(f"Checking next line for vulnerability: {next_line}")
                                if "Result: VULNERABLE" in next_line:
                                    exploit_listbox.insert(tk.END, url)
                                    logging.info(f"Added vulnerable URL to exploit_listbox: {url}")
                                else:
                                    logging.info(f"URL not vulnerable: {url}")

                    # Read and display the entire file content
                    with open(output_file, "r") as f:
                        content = f.read()
                        for line in content.splitlines():
                            output_queue.put(line.strip())
                else:
                    output_queue.put("No output file found after scan completion.")
            else:
                # Fallback to stdout for non-SQLi/XSS scans
                for line in iter(running_process.stdout.readline, ''):
                    if line:
                        output_queue.put(line.strip())
                running_process.stdout.close()
                running_process.wait()

            progress_bar.stop()

            # Enable the exploit button if there are vulnerable URLs
            if exploit_listbox.size() > 0:
                exploit_button.config(state=tk.NORMAL)
                logging.info(f"Enabled exploit button. Exploit listbox size: {exploit_listbox.size()}")
            else:
                logging.info("Exploit button remains disabled. No vulnerable URLs found.")

            # Check if running_process is still valid and show pop-up
            with process_lock:
                if running_process is not None:
                    if running_process.returncode == 0:
                        output_queue.put("Penetration Testing completed successfully!")
                        root.after(0, lambda: (
                            messagebox.showinfo("Scan Complete", "Scan completed successfully!"),
                            start_button.config(state=tk.NORMAL),
                            stop_button.config(state=tk.DISABLED)
                        ))
                    else:
                        error_message = running_process.stderr.read().strip()
                        output_queue.put(f"Scan failed: {error_message}")
                        root.after(0, lambda: (
                            messagebox.showinfo("Scan Failed", f"Scan failed: {error_message}"),
                            start_button.config(state=tk.NORMAL),
                            stop_button.config(state=tk.DISABLED)
                        ))
                        
            # Clean up the PID file
            pid_file = "pentest.pid"
            if os.path.exists(pid_file):
                os.remove(pid_file)

        # Start processing output in a separate thread
        threading.Thread(target=read_output, daemon=True).start()
        root.after(100, process_queue)

    except Exception as e:
        progress_bar.stop()
        logging.error(f"Unexpected error: {str(e)}")
        messagebox.showerror("Error", f"Unexpected error: {str(e)}")
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)

# Function to stop the scan
def stop_scan():
    global running_process, nmap_process

    # Check if the PID file exists
    pid_file = "pentest.pid"
    if os.path.exists(pid_file):
        try:
            # Read the PID from the file
            with open(pid_file, "r") as f:
                pid = int(f.read().strip())

            # Send SIGTERM to stop the process
            os.kill(pid, signal.SIGTERM)
            print(f"Sent SIGTERM to process {pid}.")

            # Clean up
            with process_lock:
                if running_process:
                    running_process.terminate()  # Terminate the subprocess
                    running_process.wait()  # Wait for the process to fully terminate
                if nmap_process:
                    nmap_process.terminate() # Terminate the nmap process
                    nmap_process.wait() # Wait for the process to fully terminate

            # Stop the progress bar and update GUI
            progress_bar.stop()
            messagebox.showinfo("Scan Stopped", "The scan has been stopped.")
            start_button.config(state=tk.NORMAL)
            stop_button.config(state=tk.DISABLED)

            # Remove the PID file
            os.remove(pid_file)
        except ProcessLookupError:
            print("Process not found. It may have already completed.")
            if os.path.exists(pid_file):
                os.remove(pid_file)  # Clean up the PID file
        except Exception as e:
            print(f"Error stopping the scan: {e}")
    else:
        # If the PID file doesn't exist, assume the scan is already stopped
        print("No scan is running.")
        progress_bar.stop()
        messagebox.showinfo("Scan Status", "No scan is currently running.")
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)

    # Reset running_process after cleanup
    with process_lock:
        running_process = None
        nmap_process = None
    
# Function to process the output queue
def process_queue():
    try:
        while True:
            line = output_queue.get_nowait()
            if line is None:
                break
            result_textbox.insert(tk.END, line + "\n", "green_text")
            result_textbox.see(tk.END) 
            columns = line.split("|")
            if len(columns) == 3 and ("SQL Injection" in columns[0] or "Cross-Site Scripting" in columns[0] or "DOM-based XSS" in columns[0]): 
                # Clear previous entries to ensure only one result
                result_table.delete(*result_table.get_children())
                result_table.insert("", "end", values=(columns[0], columns[1], columns[2]))
    except queue.Empty:
        pass
    root.after(100, process_queue)

# Function to clear URL entry placeholder
def on_url_entry_click(event):
    if url_entry.get() == "Enter target URL here":
        url_entry.delete(0, tk.END)

# Function to run Nmap scan
def run_nmap_scan(target_url, scan_type):
    if not target_url or target_url == "Enter target URL here":
        messagebox.showerror("Error", "Please enter a valid target URL.")
        return

    # Clear previous results
    nmap_textbox.delete("1.0", tk.END)

    # Define Nmap commands based on scan type
    if scan_type == "Quick Scan":
        command = ["nmap", "-T4", "-F", target_url]
    elif scan_type == "Full Scan":
        command = ["nmap", "-T4", "-A", target_url]
    elif scan_type == "OS Detection":
        # Check if the user has root privileges
        if os.geteuid() != 0:
            messagebox.showerror("Error", "OS Detection requires root privileges. Please run the application as root or use 'sudo'.")
            return
        command = ["nmap", "-T4", "-O", target_url]
    elif scan_type == "Service Version Detection":
        command = ["nmap", "-T4", "-sV", target_url]
    elif scan_type == "Script Scan":
        command = ["nmap", "-T4", "-sC", target_url]
    elif scan_type == "VS":
        command = ["nmap", "-sV", "--script", "http-vuln*", "-T4", target_url]
    elif scan_type == "Vulnerability Scan":
        command = ["nmap", "-sV", "--script", "vulners.nse", "-T4", target_url]
    elif scan_type == "Custom Scan":
        custom_options = simpledialog.askstring("Custom Scan", "Enter Nmap options (e.g., -sV -O -p 80):")
        if not custom_options:
            messagebox.showerror("Error", "No custom options provided.")
            return
        command = ["nmap"] + custom_options.split() + [target_url]
    else:
        messagebox.showerror("Error", "Invalid scan type selected.")
        return

    # Disable the Start button and enable the Stop button
    start_nmap_button.config(state=tk.DISABLED)
    stop_nmap_button.config(state=tk.NORMAL)

    # Run Nmap scan
    global nmap_process
    nmap_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Function to read and display real-time output
    def read_output():
        global nmap_process

        while True:
            with process_lock:
                if nmap_process is None:
                    break

            output = nmap_process.stdout.readline()
            if output == '' and nmap_process.poll() is not None:
                break
            if output:
                nmap_textbox.insert(tk.END, output, "green_text") # Insert with green_text tag
                nmap_textbox.see(tk.END)  # Scroll to the end
        with process_lock:
            if nmap_process is not None:
                nmap_process.stdout.close()
                nmap_process.wait()

        # Re-enable the Start button and disable the Stop button
        start_nmap_button.config(state=tk.NORMAL)
        stop_nmap_button.config(state=tk.DISABLED)

        with process_lock:
            if nmap_process is not None and nmap_process.returncode == 0:
                nmap_textbox.insert(tk.END, "\nNmap scan completed successfully!\n")
            else:
                error = nmap_process.stderr.read() if nmap_process else "Nmap process was not started."
                nmap_textbox.insert(tk.END, f"\nError: {error}\n")

    # Start reading output in a separate thread
    threading.Thread(target=read_output, daemon=True).start()

def auto_exploit_xss():
    # Check if a URL is selected in the listbox
    selected = exploit_listbox.curselection()
    if not selected:
        messagebox.showwarning("Exploit Failed", "Please select a URL to exploit.")
        return
    
    url = exploit_listbox.get(selected[0])
    scan_type = scan_type_var.get()

    if not url:
        messagebox.showwarning("Exploit Failed", "No URL selected for exploitation.")
        return
    
        # Add a header for the exploit section
    result_textbox.insert(tk.END, "\n----- STARTING XSS EXPLOITATION -----\n", "auto_header")

    # Exploit the selected URL
    try:
        # Construct a simple exploit payload (e.g., alert)
        exploit_payload = "<img src=x onerror=alert('Exploited_XSS')>"
        # Replace the original payload with the exploit payload
        exploit_url = url.replace('"/></script><script>confirm(1)</script>', exploit_payload)

        # Log the exploit attempt
        result_textbox.insert(tk.END, f"Exploiting {url}\n", "green_text")
        result_textbox.insert(tk.END, f"Exploit URL: {exploit_url}\n", "green_text")
        result_textbox.see(tk.END)

        # Open the URL in the browser
        webbrowser.open(exploit_url)
        result_textbox.insert(tk.END, "Exploit executed. Check your browser for an alert.\n", "green_text")

    except Exception as e:
        logging.error(f"Error in XSS exploit: {str(e)}")
        result_textbox.insert(tk.END, f"Error exploiting {url}: {str(e)}\n", "error_text")

    result_textbox.insert(tk.END, "\n----- XSS EXPLOITATION COMPLETE -----\n", "auto_header")
    result_textbox.see(tk.END)
    
def auto_exploit():
    # Assuming vulnerabilities are found, run the exploit script
    try:
        exploit_script = "./exploit.sh"
        if os.path.exists(exploit_script):
            # Add a header for the exploit section
            nmap_textbox.insert(tk.END, "\n----- STARTING AUTOMATED EXPLOITATION -----\n", "auto_header")

            exploit_process = subprocess.Popen([exploit_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # Read and display output from exploit script
            def read_exploit_output():
                for line in iter(exploit_process.stdout.readline, ''):
                    if line:
                        nmap_textbox.insert(tk.END, line.strip())  # Output exploit script result in textbox
                        nmap_textbox.see(tk.END)

                # After completion
                exploit_process.stdout.close()
                exploit_process.wait()
                nmap_textbox.insert(tk.END, "\n----- EXPLOITATION COMPLETE -----\n", "auto_header")

            threading.Thread(target=read_exploit_output, daemon=True).start()
        else:
            messagebox.showerror("Error", "Exploit script not found. Ensure 'exploit.sh' is in the same directory.")
    except Exception as e:
        logging.error(f"Error in exploit: {str(e)}")
        messagebox.showerror("Error", f"Error executing exploit: {str(e)}")

# Function to stop Nmap scan
def stop_nmap_scan():
    global nmap_process

    if nmap_process:
        nmap_process.terminate()  # Terminate the process
        nmap_process = None
        nmap_textbox.insert(tk.END, "\nNmap scan stopped by user.\n")
        start_nmap_button.config(state=tk.NORMAL)
        stop_nmap_button.config(state=tk.DISABLED)

# Function to export Nmap results
def export_nmap_results():
    results = nmap_textbox.get("1.0", tk.END)
    if not results.strip():
        messagebox.showwarning("Export Failed", "No Nmap results to export.")
        return

    # Ask the user to choose a file format
    file_format = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv"), ("XML Files", "*.xml")]
    )

    if file_format:
        with open(file_format, "w") as file:
            file.write(results)
        messagebox.showinfo("Export Successful", f"Nmap results exported to {file_format}")

# Function to run Subjack scan
def run_subjack_scan():
    target_domain = subjack_entry.get().strip()
    if not target_domain or target_domain == "Enter target domain here":
        messagebox.showerror("Error", "Please enter a valid target domain.")
        return

    # Clear previous results
    subjack_textbox.delete("1.0", tk.END)
    
    # Check if Subjack is installed
    try:
        subprocess.run(["subjack", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except FileNotFoundError:
        subjack_textbox.insert(tk.END, "Error: Subjack not found. Please ensure it's installed and in your PATH.\n")
        subjack_textbox.insert(tk.END, "Installation: go install github.com/haccer/subjack@latest\n")
        return
    
    # Disable the Start button and enable the Stop button
    start_subjack_button.config(state=tk.DISABLED)
    stop_subjack_button.config(state=tk.NORMAL)
    
    # Prepare command
    output_file = f"subjack_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    command = [
        "subjack",
        "-d", target_domain,
        "-o", output_file,
        "-ssl",
        "-a"  # All checks, not just subdomains with valid DNS records
    ]
    
    if subjack_wordlist_var.get():
        wordlist = subjack_wordlist_entry.get().strip()
        if wordlist:
            command.extend(["-w", wordlist])
    
    if subjack_timeout_var.get():
        timeout = subjack_timeout_spinbox.get()
        command.extend(["-t", timeout])
    
    # Run Subjack scan
    global subjack_process
    subjack_process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Function to read and display real-time output
    def read_output():
        for line in iter(subjack_process.stdout.readline, ''):
            if line:
                subjack_textbox.insert(tk.END, line)
                subjack_textbox.see(tk.END)
        
        subjack_process.stdout.close()
        subjack_process.wait()
        
        # Check if output file exists and read results
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            try:
                with open(output_file, 'r') as file:
                    results = json.load(file)
                    subjack_textbox.insert(tk.END, "\n\n=== Scan Results ===\n")
                    for result in results:
                        if 'vulnerable' in result and result['vulnerable']:
                            subjack_textbox.insert(tk.END, f"\nVulnerable subdomain found: {result['name']}\n", "vulnerable_text")
                            subjack_textbox.insert(tk.END, f"Service: {result['service']}\n")
                        else:
                            subjack_textbox.insert(tk.END, f"\nChecked: {result['name']}\n")
                    
                    # Add to results table if vulnerabilities found
                    vulnerabilities = [r for r in results if 'vulnerable' in r and r['vulnerable']]
                    if vulnerabilities:
                        result_table.insert("", "end", values=(
                            f"Subdomain Takeover ({len(vulnerabilities)} found)",
                            "High",
                            "Fix DNS configurations"
                        ))
            except json.JSONDecodeError:
                subjack_textbox.insert(tk.END, "\nNo vulnerable subdomains found.\n")
        else:
            subjack_textbox.insert(tk.END, "\nNo results file created or it's empty.\n")
        
        # Re-enable the Start button and disable the Stop button
        start_subjack_button.config(state=tk.NORMAL)
        stop_subjack_button.config(state=tk.DISABLED)
    
    # Start reading output in a separate thread
    threading.Thread(target=read_output, daemon=True).start()

# Function to stop Subjack scan
def stop_subjack_scan():
    global subjack_process
    if subjack_process:
        subjack_process.terminate()
        subjack_textbox.insert(tk.END, "\nScan stopped by user.\n")
        start_subjack_button.config(state=tk.NORMAL)
        stop_subjack_button.config(state=tk.DISABLED)

# Function to export Subjack results
def export_subjack_results():
    results = subjack_textbox.get("1.0", tk.END)
    if not results.strip():
        messagebox.showwarning("Export Failed", "No Subjack results to export.")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    
    if file_path:
        with open(file_path, "w") as file:
            file.write(results)
        messagebox.showinfo("Export Successful", f"Subjack results exported to {file_path}")

# Create the main window
root = tk.Tk()
root.title("Web Application Penetration Testing Framework")
root.geometry("1000x700")
root.minsize(800, 600)

# Create a notebook (tabbed interface)
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

# Add the existing scan results tab
existing_tab = ttk.Frame(notebook)
notebook.add(existing_tab, text="Scan Results")

# Add a new tab for Nmap scans
nmap_tab = ttk.Frame(notebook)
notebook.add(nmap_tab, text="Nmap Scan")

# Header Section
header_frame = tk.Frame(existing_tab)
header_frame.pack(fill='x', pady=10)

# Load the logo image
try:
    logo_image = tk.PhotoImage(file="WAPTF.png")  
    logo_image = logo_image.subsample(14, 14) 
    logo_label = tk.Label(header_frame, image=logo_image)
    logo_label.image = logo_image  # Keep a reference to prevent garbage collection
except tk.TclError:
    logo_label = tk.Label(header_frame, text="[LOGO]", font=("Arial", 24, "bold"))

logo_label.pack(side="left", padx=10)
title_label = tk.Label(header_frame, text="Web App Penetration Testing Framework", font=("Arial", 20, "bold"))
title_label.pack(side="left")
settings_button = tk.Button(header_frame, text="Settings", command=open_settings)
settings_button.pack(side="right", padx=10)
help_button = tk.Button(header_frame, text="Help", command=open_help)
help_button.pack(side="right", padx=10)

# Input Fields Section
input_frame = tk.Frame(existing_tab)
input_frame.pack(pady=20)
url_label = tk.Label(input_frame, text="Target URL:")
url_label.grid(row=0, column=0, padx=10, pady=5)
url_entry = tk.Entry(input_frame, width=50)
url_entry.grid(row=0, column=1, padx=10, pady=5)
url_entry.insert(0, "Enter target URL here")
url_entry.bind("<FocusIn>", on_url_entry_click)
clear_button = tk.Button(input_frame, text="Clear", command=lambda: url_entry.delete(0, tk.END))
clear_button.grid(row=0, column=2, padx=10, pady=5)

# Scan Controls Section
scan_frame = tk.Frame(existing_tab)
scan_frame.pack(pady=20)
scan_label = tk.Label(scan_frame, text="Select Scan Type:")
scan_label.grid(row=0, column=0, padx=10, pady=5)
scan_types = ["SQLi", "XSS", "Simple XSS", "Comprehensive"]
scan_type_var = tk.StringVar(value=scan_types[0])
scan_type_menu = ttk.OptionMenu(scan_frame, scan_type_var, "XSS", *scan_types)
scan_type_menu.grid(row=0, column=1, padx=10, pady=5)
depth_label = tk.Label(scan_frame, text="Scan Depth:")
depth_label.grid(row=1, column=0, padx=10, pady=5)
depth_spinbox = tk.Spinbox(scan_frame, from_=1, to=10, width=5)
depth_spinbox.grid(row=1, column=1, padx=10, pady=5)
timeout_label = tk.Label(scan_frame, text="Timeout (seconds):")
timeout_label.grid(row=2, column=0, padx=10, pady=5)
timeout_spinbox = tk.Spinbox(scan_frame, from_=1, to=60, width=5)
timeout_spinbox.grid(row=2, column=1, padx=10, pady=5)

# Start Scan Button
start_button = tk.Button(input_frame, text="Start Scan", command=start_testing)
start_button.grid(row=1, column=0, padx=10, pady=5)

# Stop Scan Button
stop_button = tk.Button(input_frame, text="Stop Scan", command=stop_scan, state=tk.DISABLED)
stop_button.grid(row=1, column=1, padx=10, pady=5)

# Progress Bar
progress_bar = ttk.Progressbar(input_frame, orient="horizontal", length=300, mode="indeterminate")
progress_bar.grid(row=1, column=2, padx=10, pady=5)

# Exploit Listbox Section
exploit_frame = tk.Frame(existing_tab)
exploit_frame.pack(pady=10)
exploit_label = tk.Label(exploit_frame, text="Select URL to Exploit:")
exploit_label.grid(row=0, column=0, padx=10, pady=5)
exploit_listbox = tk.Listbox(exploit_frame, width=80, height=5)
exploit_listbox.grid(row=0, column=1, padx=10, pady=5)

# Results Section
results_frame = tk.Frame(existing_tab)
results_frame.pack(pady=20)
result_label = tk.Label(results_frame, text="Scan Results:")
result_label.grid(row=0, column=0, padx=10, pady=5)
result_table = ttk.Treeview(results_frame, columns=("Vulnerability", "Severity", "Action"), show="headings", height=3)
result_table.grid(row=1, column=0, columnspan=3, padx=5, pady=2, sticky="nsew")
result_table.heading("Vulnerability", text="Vulnerability")
result_table.heading("Severity", text="Severity")
result_table.heading("Action", text="Action")
result_table.column("Vulnerability", width=300)
result_table.column("Severity", width=150)
result_table.column("Action", width=300)
result_table.grid(row=2, column=0, columnspan=3, padx=5, pady=2, sticky="nsew")

# Add a Text widget for detailed results
result_textbox = tk.Text(results_frame, wrap=tk.WORD, height=5, width=80)
result_textbox.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

results_frame.columnconfigure(0, weight=1)
results_frame.rowconfigure(1, weight=1)
results_frame.rowconfigure(2, weight=1)
results_frame.pack(pady=20, fill="both", expand=True)

# Configure green text tag
result_textbox.tag_configure("green_text", foreground="green", font=("Courier", 12))
result_textbox.tag_configure("auto_header", foreground="red", font=("Courier", 12, "bold"))
result_textbox.tag_configure("error_text", foreground="red", font=("Courier", 12, "bold"))

# Footer Section
footer_frame = tk.Frame(existing_tab)
footer_frame.pack(fill='x', side='bottom', pady=5)
contact_button = tk.Button(footer_frame, text="Contact Support", command=contact_support)
contact_button.pack(side="left", padx=10)
pdf_button = tk.Button(footer_frame, text="Export Results as PDF", command=export_to_pdf)
pdf_button.pack(side="left", padx=10)
# Add an Exploit button
exploit_button = tk.Button(footer_frame, text="Exploit XSS", command=lambda: auto_exploit_xss(), bg="#ff9999", font=("Arial", 10, "bold"), state=tk.DISABLED)
exploit_button.pack(side="left", padx=10)
copyright_button = tk.Button(footer_frame, text="Copyright", command=show_copyright)
copyright_button.pack(side="right", padx=10)


# Nmap Scan Tab Components
nmap_url_frame = tk.Frame(nmap_tab)
nmap_url_frame.pack(fill='x', pady=10)

nmap_url_label = tk.Label(nmap_url_frame, text="Target URL for Nmap Scan:")
nmap_url_label.pack(side="left", padx=10)

nmap_url_entry = tk.Entry(nmap_url_frame, width=50)
nmap_url_entry.pack(side="left", padx=10)
nmap_url_entry.insert(0, "Enter target URL here")
nmap_url_entry.bind("<FocusIn>", lambda event: nmap_url_entry.delete(0, tk.END))

nmap_clear_button = tk.Button(nmap_url_frame, text="Clear", command=lambda: nmap_url_entry.delete(0, tk.END))
nmap_clear_button.pack(side="left", padx=10)

# Dropdown for Nmap scan types
nmap_scan_types = ["Quick Scan", "Full Scan", "OS Detection", "Service Version Detection", "Script Scan", "VS", "Vulnerability Scan", "Custom Scan"]
nmap_scan_type_var = tk.StringVar(value=nmap_scan_types[0])
nmap_scan_dropdown = ttk.Combobox(nmap_url_frame, textvariable=nmap_scan_type_var, values=nmap_scan_types, state="readonly")
nmap_scan_dropdown.pack(side="left", padx=10)

nmap_textbox = tk.Text(nmap_tab, wrap=tk.WORD, height=20, width=80, font=("Courier", 12))
nmap_textbox.pack(fill="both", expand=True, padx=10, pady=10)

# Configure text tags for different colors and sizes
nmap_textbox.tag_configure("green_text", foreground="green", font=("Courier", 12))
nmap_textbox.tag_configure("success_text", foreground="green", font=("Courier", 12, "bold"))
nmap_textbox.tag_configure("error_text", foreground="red", font=("Courier", 12, "bold"))
nmap_textbox.tag_configure("auto_header", foreground="red", font=("Courier", 12, "bold"))

# Button to Start Exploit 
automate_button = tk.Button(nmap_tab, text="Automate", command=auto_exploit, bg="#ff9999", font=("Arial", 10, "bold"))
automate_button.pack(side="left", pady=10, padx=10)

# Button to start Nmap scan
start_nmap_button = tk.Button(nmap_tab, text="Start Nmap Scan", command=lambda: run_nmap_scan(nmap_url_entry.get().strip(), nmap_scan_type_var.get()))
start_nmap_button.pack(pady=10)

# Button to stop Nmap scan
stop_nmap_button = tk.Button(nmap_tab, text="Stop Nmap Scan", command=stop_nmap_scan, state=tk.DISABLED)
stop_nmap_button.pack(pady=10)

# Button to export Nmap results
export_nmap_button = tk.Button(nmap_tab, text="Export Nmap Results", command=export_nmap_results)
export_nmap_button.pack(pady=10)

# Create a tab for Subjack
subjack_tab = ttk.Frame(notebook)
notebook.add(subjack_tab, text="Subdomain Takeover")

# Subjack Tab Components
subjack_frame = tk.Frame(subjack_tab)
subjack_frame.pack(fill='x', pady=10)

subjack_label = tk.Label(subjack_frame, text="Target Domain:")
subjack_label.grid(row=0, column=0, padx=10, pady=5)

subjack_entry = tk.Entry(subjack_frame, width=50)
subjack_entry.grid(row=0, column=1, padx=10, pady=5)
subjack_entry.insert(0, "Enter target domain here")
subjack_entry.bind("<FocusIn>", lambda event: subjack_entry.delete(0, tk.END) if subjack_entry.get() == "Enter target domain here" else None)

# Options frame
subjack_options_frame = tk.Frame(subjack_tab)
subjack_options_frame.pack(fill='x', pady=5)

# Wordlist option
subjack_wordlist_var = tk.BooleanVar(value=False)
subjack_wordlist_check = tk.Checkbutton(subjack_options_frame, text="Use custom wordlist:", variable=subjack_wordlist_var)
subjack_wordlist_check.grid(row=0, column=0, padx=5, pady=5)

subjack_wordlist_entry = tk.Entry(subjack_options_frame, width=30)
subjack_wordlist_entry.grid(row=0, column=1, padx=5, pady=5)
subjack_wordlist_browse = tk.Button(subjack_options_frame, text="Browse", 
                                   command=lambda: subjack_wordlist_entry.insert(0, filedialog.askopenfilename()))
subjack_wordlist_browse.grid(row=0, column=2, padx=5, pady=5)

# Timeout option
subjack_timeout_var = tk.BooleanVar(value=False)
subjack_timeout_check = tk.Checkbutton(subjack_options_frame, text="Custom timeout:", variable=subjack_timeout_var)
subjack_timeout_check.grid(row=1, column=0, padx=5, pady=5)

subjack_timeout_spinbox = tk.Spinbox(subjack_options_frame, from_=1, to=60, width=5)
subjack_timeout_spinbox.grid(row=1, column=1, padx=5, pady=5)

# Results display
subjack_textbox = scrolledtext.ScrolledText(subjack_tab, wrap=tk.WORD, height=20, width=80)
subjack_textbox.pack(fill="both", expand=True, padx=10, pady=10)

# Configure text tags
subjack_textbox.tag_configure("vulnerable_text", foreground="red", font=("Courier", 12, "bold"))

# Control buttons
subjack_button_frame = tk.Frame(subjack_tab)
subjack_button_frame.pack(fill='x', pady=10)

start_subjack_button = tk.Button(subjack_button_frame, text="Start Scan", command=run_subjack_scan)
start_subjack_button.pack(side="left", padx=10)

stop_subjack_button = tk.Button(subjack_button_frame, text="Stop Scan", command=stop_subjack_scan, state=tk.DISABLED)
stop_subjack_button.pack(side="left", padx=10)

export_subjack_button = tk.Button(subjack_button_frame, text="Export Results", command=export_subjack_results)
export_subjack_button.pack(side="left", padx=10)

# Queue for thread-safe communication
output_queue = queue.Queue()

# Run the Tkinter event loop
root.mainloop()