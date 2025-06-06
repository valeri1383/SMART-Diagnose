def check_install_libraries():
    """Check if required libraries are installed and install missing ones."""
    import importlib
    import subprocess
    import sys

    # List of required packages
    required_libs = ["matplotlib", "pandas", "firebase_admin", "psutil", "pyttsx3", "requests", "openai"]

    for lib in required_libs:
        try:
            importlib.import_module(lib)
            print(f"✓ {lib} is installed")
        except ImportError:
            print(f"Installing {lib}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
            print(f"✓ {lib} installed successfully")


# Call the function before any imports
check_install_libraries()

import tkinter as tk
from tkinter import ttk
import Software_AI_Scan, MacOS_Hardware_AI_Scan, Chat_with_AI_agent, AI_optimiser, AI_security_scanner, \
    AI_software_recommender, Dashboard_Overview, Windows_Hardware_AI_Scan
import platform


class TestingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SMART-Diagnose")

        # Get current operating system
        self.current_os = platform.system()

        # Platform-specific window size
        if self.current_os == "Darwin":  # macOS
            self.root.geometry("950x880")
        else:  # Windows - smaller to fit screen better
            self.root.geometry("850x780")

        # Initialize StringVar for OS selection first
        self.os_var = tk.StringVar(value="MacOS")  # Set default value

        # Define default button titles
        self.windows_titles = ["1. 🤖 AI Hardware Scanning",
                               "2. 🤖 AI Software Scanning",
                               "3. 🔍 AI Optimiser",
                               "4. ⚡ AI Security Scanner",
                               "5. 📱 AI Application Recommender",
                               "6. 💬 Chat with AI Consultant",
                               "7. 📊 Dashboard Visualisation",
                               "8. 🚪 Exit"]
        self.macos_titles = ["1. 🤖 AI Hardware Scanning",
                             "2. 🤖 AI Software Scanning",
                             "3. 🔍 AI Optimiser",
                             "4. ⚡ AI Security Scanner",
                             "5. 📱 AI Application Recommender",
                             "6. 💬 Chat with AI Consultant",
                             "7. 📊 Dashboard Visualisation",
                             "8. 🚪 Exit"]

        # Create a custom style for the buttons
        self.style = ttk.Style()

        # Configure button style with platform-specific adjustments
        if self.current_os == "Darwin":  # macOS
            self.style.configure('Responsive.TButton',
                                 padding=(20, 9),
                                 font=('Arial', 22, 'bold'),
                                 borderwidth=2,
                                 width=30,
                                 height=2.3)
        else:  # Windows
            self.style.configure('Responsive.TButton',
                                 padding=(12, 6),
                                 font=('Arial', 16, 'bold'),
                                 borderwidth=2,
                                 width=26,
                                 height=1.7)

        # Button states styling - consistent across platforms
        self.style.map('Responsive.TButton',
                       foreground=[('pressed', '#FF4444'),
                                   ('active', '#2196F3'),
                                   ('!disabled', '#333333')],
                       background=[('pressed', '#E0E0E0'),
                                   ('active', '#F5F5F5'),
                                   ('!disabled', '#FFFFFF')],
                       relief=[('pressed', 'sunken'),
                               ('!pressed', 'raised')],
                       borderwidth=[('pressed', 3),
                                    ('!pressed', 2)])

        # Create and configure main frame with platform-specific padding
        main_padding = "15" if self.current_os == "Darwin" else "12"
        self.main_frame = ttk.Frame(self.root, padding=main_padding)
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure column and row weights for centering
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Create a header frame for title and OS selection
        self.header_frame = ttk.Frame(self.main_frame)
        self.header_frame.grid(row=0, column=0, pady=8)

        # Add title with platform-specific font
        title_font_size = 28 if self.current_os == "Darwin" else 22
        self.title_label = ttk.Label(self.header_frame,
                                     text="SMART-Diagnose",
                                     font=('Arial', title_font_size, 'bold'))
        title_pady = 8 if self.current_os == "Darwin" else 8
        self.title_label.grid(row=0, column=0, pady=title_pady)

        # OS selection label with platform-specific font
        os_label_font_size = 18 if self.current_os == "Darwin" else 14
        self.os_label = ttk.Label(self.header_frame,
                                  text="Select Operating System:",
                                  font=('Arial', os_label_font_size, 'bold'))
        self.os_label.grid(row=1, column=0, pady=6)

        # Dropdown style - platform-specific
        dropdown_padding = 8 if self.current_os == "Darwin" else 4
        self.style.configure('TCombobox',
                             padding=dropdown_padding,
                             font=('Arial', 10))

        # Dropdown with platform-specific settings
        dropdown_font_size = 16 if self.current_os == "Darwin" else 12
        dropdown_width = 18 if self.current_os == "Darwin" else 14
        self.os_dropdown = ttk.Combobox(self.header_frame,
                                        textvariable=self.os_var,
                                        values=["MacOS", "Windows"],
                                        state="readonly",
                                        font=('Arial', dropdown_font_size),
                                        width=dropdown_width)
        dropdown_pady = 10 if self.current_os == "Darwin" else 8
        self.os_dropdown.grid(row=2, column=0, pady=dropdown_pady)
        self.os_dropdown.bind('<<ComboboxSelected>>', self.on_os_select)

        # Create a divider for visual separation
        self.divider = ttk.Separator(self.main_frame, orient='horizontal')
        divider_pady = 15 if self.current_os == "Darwin" else 12
        self.divider.grid(row=1, column=0, sticky="ew", pady=divider_pady)

        # Frame for buttons with platform-specific padding
        button_frame_padding = "8" if self.current_os == "Darwin" else "6"
        self.button_frame = ttk.Frame(self.main_frame, padding=button_frame_padding)
        button_frame_pady = 10 if self.current_os == "Darwin" else 8
        self.button_frame.grid(row=2, column=0, pady=button_frame_pady)
        self.button_frame.grid_columnconfigure(0, weight=1)

        # Button container with platform-specific settings
        border_width = 2 if self.current_os == "Darwin" else 1
        self.button_container = ttk.Frame(self.button_frame, relief="groove", borderwidth=border_width)
        container_padx = 15 if self.current_os == "Darwin" else 12
        self.button_container.grid(row=0, column=0, padx=container_padx)
        self.button_container.grid_columnconfigure(0, weight=1)

        # Store buttons in a list for easy access
        self.buttons = []

        # Variable to track currently focused button
        self.focused_button_index = 0

        # Initialize the buttons with default OS selection
        self.on_os_select(None)  # Call on_os_select to create initial buttons

        # Bind Enter key to the root window
        self.root.bind('<Return>', self.activate_focused_button)

        # Bind up and down arrow keys for navigation
        self.root.bind('<Up>', lambda event: self.change_focus(-1))
        self.root.bind('<Down>', lambda event: self.change_focus(1))

        # Bind number keys 1-8 for direct selection
        for i in range(1, 9):
            self.root.bind(str(i), lambda event, idx=i - 1: self.button_click(idx))
            self.root.bind(f'<KP_{i}>', lambda event, idx=i - 1: self.button_click(idx))

    def on_os_select(self, event):
        # Clear existing buttons
        for button in self.buttons:
            button.destroy()
        self.buttons.clear()

        # Create new buttons based on OS selection
        num_buttons = 8
        titles = self.windows_titles if self.os_var.get() == "Windows" else self.macos_titles

        for i in range(num_buttons):
            btn = ttk.Button(self.button_container,
                             text=titles[i],
                             style='Responsive.TButton',
                             command=lambda x=i: self.button_click(x))

            btn.bind('<Enter>', lambda e, btn=btn: self.on_hover(e, btn))
            btn.bind('<Leave>', lambda e, btn=btn: self.on_leave(e, btn))

            # Add focus events for highlighting currently selected button
            btn.bind('<FocusIn>', lambda e, i=i: self.on_focus_in(i))
            btn.bind('<FocusOut>', self.on_focus_out)

            # Platform-specific button spacing
            btn_pady = 8 if self.current_os == "Darwin" else 5
            btn_padx = 20 if self.current_os == "Darwin" else 15
            btn.grid(row=i, column=0, pady=btn_pady, padx=btn_padx, sticky="ew")
            self.buttons.append(btn)

        # Set focus to the first button by default
        if self.buttons:
            self.focused_button_index = 0
            self.buttons[0].focus_set()

    def highlight_button(self, button_num):
        """Temporarily highlight a button to show it was activated by keyboard"""
        if 0 <= button_num < len(self.buttons):
            # First set focus to the button
            self.buttons[button_num].focus_set()
            self.focused_button_index = button_num

            # Then add the pressed visual effect
            self.buttons[button_num].state(['pressed'])
            self.root.after(150, lambda: self.buttons[button_num].state(['!pressed']))

    def change_focus(self, direction):
        """Change focus to next/previous button"""
        if not self.buttons:
            return

        # Calculate new index with wraparound
        new_index = (self.focused_button_index + direction) % len(self.buttons)
        self.focused_button_index = new_index

        # Set focus to the new button
        self.buttons[new_index].focus_set()

    def on_focus_in(self, index):
        """Handle button focus in event"""
        self.focused_button_index = index
        # Additional visual feedback for keyboard focus
        self.buttons[index].state(['active'])

    def on_focus_out(self, event):
        """Handle button focus out event"""
        btn = event.widget
        btn.state(['!active'])

    def activate_focused_button(self, event):
        """Activate the currently focused button when Enter is pressed"""
        if 0 <= self.focused_button_index < len(self.buttons):
            self.button_click(self.focused_button_index)
            # Add visual feedback
            self.buttons[self.focused_button_index].state(['pressed'])
            self.root.after(150, lambda: self.buttons[self.focused_button_index].state(['!pressed']))

    def set_button_title(self, os_type, button_index, new_title):
        if os_type == "Windows" and button_index < len(self.windows_titles):
            self.windows_titles[button_index] = new_title
        elif os_type == "MacOS" and button_index < len(self.macos_titles):
            self.macos_titles[button_index] = new_title

        if self.os_var.get() == os_type and self.buttons:
            self.buttons[button_index].configure(text=new_title)

    def button_click(self, button_num):
        # Make sure button_num is valid
        if not (0 <= button_num < len(self.buttons)):
            return

        # Provide visual feedback for the button press
        self.highlight_button(button_num)

        btn = self.buttons[button_num]
        print(f"{btn['text']} clicked!")

        # Get current OS selection
        current_os = self.os_var.get()

        if current_os == "Windows":
            if button_num == 0:  # AI Hardware Scanning for Windows
                print("Starting Windows AI Hardware Scan...")
                Windows_Hardware_AI_Scan.windows_hardware_scan(self.root)


            elif button_num == 1:  # AI Software Scanning for Windows
                print("Starting Windows AI Software Scan...")
                Software_AI_Scan.create_system_analyzer()

            elif button_num == 2:  # AI Optimiser for Windows
                print("Starting Windows AI Optimiser...")
                AI_optimiser.create_ai_optimizer()

            elif button_num == 3:  # Security Scanner for Windows
                print("Starting Windows Security Scan...")
                AI_security_scanner.create_security_scanner()

            elif button_num == 4:  # Application Recommender for Windows
                print("Starting Windows Application Recommender...")
                AI_software_recommender.create_app_recommender()

            elif button_num == 5:  # Chat with AI Consultant for Windows
                print("Opening Windows AI Chat Console...")
                Chat_with_AI_agent.create_mistral_chat()

            elif button_num == 6:  # Dashboard Visualisation for Windows
                print("Dashboard Visualisation...")
                Dashboard_Overview.create_test_results_dashboard()

            elif button_num == 7:  # Exit
                print("Exiting Windows application...")
                self.root.quit()
                self.root.destroy()  # Force destroy the window

        elif current_os == "MacOS":
            if button_num == 0:  # AI Hardware Scanning for MacOS
                print("Starting MacOS AI Hardware Scan...")
                MacOS_Hardware_AI_Scan.show_macos_scan_window(self.root)

            elif button_num == 1:  # AI Software Scanning for MacOS
                print("Starting MacOS AI Software Scan...")
                Software_AI_Scan.create_system_analyzer()


            elif button_num == 2:  # AI Optimiser for MacOS
                print("Starting MacOS AI Optimiser...")
                AI_optimiser.create_ai_optimizer()

            elif button_num == 3:  # Security Scanner for MacOS
                print("Starting MacOS Security Scan...")
                AI_security_scanner.create_security_scanner()

            elif button_num == 4:  # Application Recommender for MacOS
                print("Starting MacOS Application Recommender...")
                AI_software_recommender.create_app_recommender()

            elif button_num == 5:  # Chat with AI Consultant for MacOS
                print("Launching MacOS AI Assistant...")
                Chat_with_AI_agent.create_mistral_chat()

            elif button_num == 6:  # Dashboard visualisation for MacOS
                print("Dashboard Visualisation...")
                Dashboard_Overview.create_test_results_dashboard()

            elif button_num == 7:  # Exit
                print("Exiting MacOS application...")
                self.root.quit()
                self.root.destroy()  # Force destroy the window

    def on_hover(self, event, button):
        button.state(['active'])

    def on_leave(self, event, button):
        # Only remove active state if this button is not the focused one
        if self.buttons[self.focused_button_index] != button:
            button.state(['!active'])


# Add proper exit handler for the main window
def on_exit():
    print("Exiting application...")
    # Cancel all scheduled after events
    for after_id in root.tk.call('after', 'info'):
        root.after_cancel(after_id)
    # Now it's safe to quit and destroy
    root.quit()
    root.destroy()
    # Force exit if the application is still running
    import sys
    sys.exit(0)


root = tk.Tk()
app = TestingApp(root)
# Bind the exit protocol
root.protocol("WM_DELETE_WINDOW", on_exit)
# Also bind Escape key to exit
root.bind('<Escape>', lambda e: on_exit())
root.mainloop()