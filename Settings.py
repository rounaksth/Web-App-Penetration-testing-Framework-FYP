import tkinter as tk
from tkinter import ttk, messagebox

class SettingsWindow:
    def __init__(self, root):
        self.root = root
        self.settings_window = tk.Toplevel(root)
        self.settings_window.title("Settings")
        self.settings_window.geometry("400x300")

        ttk.Label(self.settings_window, text="Settings", font=("Arial", 14, "bold")).pack(pady=10)

        # Scan Depth
        ttk.Label(self.settings_window, text="Scan Depth:").pack()
        self.scan_depth = ttk.Combobox(self.settings_window, values=["Shallow", "Moderate", "Deep"])
        self.scan_depth.pack()

        # Logging Level
        ttk.Label(self.settings_window, text="Logging Level:").pack()
        self.logging_level = ttk.Combobox(self.settings_window, values=["Low", "Medium", "High"])
        self.logging_level.pack()

        # Report Format
        ttk.Label(self.settings_window, text="Report Format:").pack()
        self.report_format = ttk.Combobox(self.settings_window, values=["PDF", "HTML", "TXT"])
        self.report_format.pack()

        # Theme Selection
        ttk.Label(self.settings_window, text="Theme:").pack()
        self.theme_selection = ttk.Combobox(self.settings_window, values=["Light", "Dark"])
        self.theme_selection.pack()

        # Buttons
        ttk.Button(self.settings_window, text="Save", command=self.save_settings).pack(pady=5)
        ttk.Button(self.settings_window, text="Reset", command=self.reset_settings).pack(pady=5)

    def save_settings(self):
        """Save settings and show confirmation"""
        messagebox.showinfo("Settings", "Settings saved successfully!")

    def reset_settings(self):
        """Reset settings to default values"""
        self.scan_depth.set("")
        self.logging_level.set("")
        self.report_format.set("")
        self.theme_selection.set("")
        messagebox.showinfo("Settings", "Settings reset to default values.")