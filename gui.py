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

# Global variable to track the running process
running_process = None

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
    if not result_table.get_children():
        messagebox.showwarning("Export Failed", "No results available to export.")
        return

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Web App Penetration Testing Results", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Arial", size=10)
    pdf.cell(60, 10, "Vulnerability", border=1)
    pdf.cell(60, 10, "Severity", border=1)
    pdf.cell(60, 10, "Action", border=1)
    pdf.ln()

    for child in result_table.get_children():
        row_data = result_table.item(child)["values"]
        pdf.cell(60, 10, str(row_data[0]), border=1)
        pdf.cell(60, 10, str(row_data[1]), border=1)
        pdf.cell(60, 10, str(row_data[2]), border=1)
        pdf.ln()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_filename = f"scan_results_{timestamp}.pdf"
    pdf_file = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")], initialfile=default_filename)
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
    global running_process  # Declare running_process as global

    target_url = url_entry.get().strip()
    scan_type = scan_type_var.get()
    scan_depth = depth_spinbox.get()
    timeout = timeout_spinbox.get()

    if not target_url or target_url == "Enter target URL here":
        messagebox.showerror("Error", "Please enter a valid target URL.")
        return

    script_path = "./pentest.sh"
    if not os.path.exists(script_path):
        messagebox.showerror("Error", "Backend script not found. Ensure 'pentest.sh' is in the same directory.")
        return
    if not os.access(script_path, os.X_OK):
        messagebox.showerror("Error", "Backend script is not executable. Please check permissions.")
        return

    command = [script_path, target_url, scan_type, scan_depth, timeout]

    # Clear previous results
    result_table.delete(*result_table.get_children())

    # Disable the "Start Scan" button and enable the "Stop Scan" button
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

    progress_bar.start()

    try:
        running_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        def read_output():
            for line in iter(running_process.stdout.readline, ''):
                if line:
                    output_queue.put(line.strip())
            running_process.stdout.close()
            running_process.wait()

            progress_bar.stop()

            # Re-enable the "Start Scan" button and disable the "Stop Scan" button
            start_button.config(state=tk.NORMAL)
            stop_button.config(state=tk.DISABLED)

            if running_process.returncode == 0:
                messagebox.showinfo("Scan Completed", "Penetration Testing completed successfully!")
            else:
                error_message = running_process.stderr.read().strip()
                messagebox.showerror("Error", f"Scan failed: {error_message}")

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
    global running_process

    if running_process:
        running_process.terminate()  # Terminate the process
        running_process = None  # Reset the running_process variable
        progress_bar.stop()
        messagebox.showinfo("Scan Stopped", "The scan has been stopped.")
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)

# Function to process the output queue
def process_queue():
    try:
        while True:
            line = output_queue.get_nowait()
            if line is None:
                break
            try:
                columns = line.split("|")
                if len(columns) == 3:
                    result_table.insert("", "end", values=columns)
                else:
                    logging.warning(f"Skipping malformed line: {line}")
            except Exception as e:
                logging.error(f"Error parsing line: {line}. Error: {e}")
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

    # Define Nmap commands based on scan type-----types
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
        while True:
            output = nmap_process.stdout.readline()
            if output == '' and nmap_process.poll() is not None:
                break
            if output:
                nmap_textbox.insert(tk.END, output)
                nmap_textbox.see(tk.END)  # Scroll to the end
        nmap_process.stdout.close()
        nmap_process.wait()

        # Re-enable the Start button and disable the Stop button
        start_nmap_button.config(state=tk.NORMAL)
        stop_nmap_button.config(state=tk.DISABLED)

        if nmap_process.returncode == 0:
            nmap_textbox.insert(tk.END, "\nNmap scan completed successfully!\n")
        else:
            error = nmap_process.stderr.read()
            nmap_textbox.insert(tk.END, f"\nError: {error}\n")

    # Start reading output in a separate thread
    threading.Thread(target=read_output, daemon=True).start()

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

# Create the main window
root = tk.Tk()
root.title("Web Application Penetration Testing Framework")
root.geometry("1000x700")

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
clear_button.grid(row=1, column=1, padx=10, pady=5, sticky="w")

# Scan Controls Section
scan_frame = tk.Frame(existing_tab)
scan_frame.pack(pady=20)
scan_label = tk.Label(scan_frame, text="Select Scan Type:")
scan_label.grid(row=0, column=0, padx=10, pady=5)
scan_types = ["SQLi", "XSS", "Comprehensive"]
scan_type_var = tk.StringVar(value=scan_types[0])
scan_dropdown = tk.OptionMenu(scan_frame, scan_type_var, *scan_types)
scan_dropdown.grid(row=0, column=1, padx=10, pady=5)
depth_label = tk.Label(scan_frame, text="Scan Depth:")
depth_label.grid(row=1, column=0, padx=10, pady=5)
depth_spinbox = tk.Spinbox(scan_frame, from_=1, to=10, width=5)
depth_spinbox.grid(row=1, column=1, padx=10, pady=5)
timeout_label = tk.Label(scan_frame, text="Timeout (seconds):")
timeout_label.grid(row=2, column=0, padx=10, pady=5)
timeout_spinbox = tk.Spinbox(scan_frame, from_=1, to=60, width=5)
timeout_spinbox.grid(row=2, column=1, padx=10, pady=5)

# Start Scan Button
start_button = tk.Button(existing_tab, text="Start Scan", command=start_testing)
start_button.pack(pady=10)

# Stop Scan Button
stop_button = tk.Button(existing_tab, text="Stop Scan", command=stop_scan, state=tk.DISABLED)
stop_button.pack(pady=10)

# Progress Bar
progress_bar = ttk.Progressbar(existing_tab, orient="horizontal", length=300, mode="indeterminate")
progress_bar.pack(pady=20)

# Results Section
results_frame = tk.Frame(existing_tab)
results_frame.pack(pady=20)
result_label = tk.Label(results_frame, text="Scan Results:")
result_label.grid(row=0, column=0, padx=10, pady=5)
result_table = ttk.Treeview(results_frame, columns=("Vulnerability", "Severity", "Action"), show="headings")
result_table.heading("Vulnerability", text="Vulnerability")
result_table.heading("Severity", text="Severity")
result_table.heading("Action", text="Action")
result_table.grid(row=1, column=0, padx=10, pady=5)

# Footer Section
footer_frame = tk.Frame(existing_tab)
footer_frame.pack(fill='x', pady=10)
contact_button = tk.Button(footer_frame, text="Contact Support", command=contact_support)
contact_button.pack(side="left", padx=10)
pdf_button = tk.Button(footer_frame, text="Export Results as PDF", command=export_to_pdf)
pdf_button.pack(side="left", padx=10)
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
nmap_scan_types = ["Quick Scan", "Full Scan", "OS Detection"]
nmap_scan_type_var = tk.StringVar(value=nmap_scan_types[0])
nmap_scan_dropdown = ttk.Combobox(nmap_url_frame, textvariable=nmap_scan_type_var, values=nmap_scan_types, state="readonly")
nmap_scan_dropdown.pack(side="left", padx=10)

nmap_textbox = tk.Text(nmap_tab, wrap=tk.WORD, height=20, width=80)
nmap_textbox.pack(fill="both", expand=True, padx=10, pady=10)

# Button to start Nmap scan
start_nmap_button = tk.Button(nmap_tab, text="Start Nmap Scan", command=lambda: run_nmap_scan(nmap_url_entry.get().strip(), nmap_scan_type_var.get()))
start_nmap_button.pack(pady=10)

# Button to stop Nmap scan
stop_nmap_button = tk.Button(nmap_tab, text="Stop Nmap Scan", command=stop_nmap_scan, state=tk.DISABLED)
stop_nmap_button.pack(pady=10)

# Button to export Nmap results
export_nmap_button = tk.Button(nmap_tab, text="Export Nmap Results", command=export_nmap_results)
export_nmap_button.pack(pady=10)

# Queue for thread-safe communication
output_queue = queue.Queue()

# Run the Tkinter event loop
root.mainloop()