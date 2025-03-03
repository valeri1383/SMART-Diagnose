import tkinter as tk
from tkinter import ttk
import MacOS_Software_AI_Scan, MacOS_Hardware_AI_Scan, Chat_with_AI_agent, AI_optimiser, AI_security_scanner, \
    AI_software_recommender


class TestingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AI System Tools")
        self.root.geometry("1100x1100")  # Increased window size

        # Initialize StringVar for OS selection first
        self.os_var = tk.StringVar(value="MacOS")  # Set default value

        # Define default button titles - moved Chat to second-to-last position and added icon to App Recommender
        self.windows_titles = ["1. 🤖 AI Hardware Scanning",
                               "2. 🤖 AI Software Scanning",
                               "3. 📊 AI Optimiser",
                               "4. ⚡ Software Scanning",
                               "5. 📱 AI Application Recommender",
                               "6. 💬 Chat with AI Consultant",
                               "7. 🚪 Exit"]
        self.macos_titles = ["1. 🤖 AI Hardware Scanning",
                             "2. 🤖 AI Software Scanning",
                             "3. 📊 AI Optimiser",
                             "4. ⚡ AI Security Scanner",
                             "5. 📱 AI Application Recommender",
                             "6. 💬 Chat with AI Consultant",
                             "7. 🚪 Exit"]

        # Create a custom style for the buttons with enhanced appearance
        self.style = ttk.Style()
        self.style.configure('Responsive.TButton',
                             padding=(30, 12),  # Increased padding for larger buttons
                             font=('Arial', 32, 'bold'),  # Larger font
                             borderwidth=3,  # Keep border thickness
                             width=35,  # Increased width
                             height=3)  # Increased height

        # Enhanced button states with more vibrant colors and effects
        self.style.map('Responsive.TButton',
                       foreground=[('pressed', '#FF4444'),  # Bright red when pressed
                                   ('active', '#2196F3'),  # Material blue on hover
                                   ('!disabled', '#333333')],  # Dark gray by default
                       background=[('pressed', '#E0E0E0'),  # Light gray when pressed
                                   ('active', '#F5F5F5'),  # Slightly lighter on hover
                                   ('!disabled', '#FFFFFF')],  # White by default
                       relief=[('pressed', 'sunken'),
                               ('!pressed', 'raised')],
                       borderwidth=[('pressed', 4),  # Border animation
                                    ('!pressed', 3)])

        # Create and configure main frame with padding
        self.main_frame = ttk.Frame(self.root, padding="20")  # Increased padding
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure column and row weights for centering
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Create a header frame for title and OS selection
        self.header_frame = ttk.Frame(self.main_frame)
        self.header_frame.grid(row=0, column=0, pady=10)

        # Add title
        self.title_label = ttk.Label(self.header_frame,
                                     text="AI System Tools",
                                     font=('Arial', 32, 'bold'))  # Larger title
        self.title_label.grid(row=0, column=0, pady=10)

        # Enhanced OS selection label
        self.os_label = ttk.Label(self.header_frame,
                                  text="Select Operating System:",
                                  font=('Arial', 20, 'bold'))  # Larger font
        self.os_label.grid(row=1, column=0, pady=10)

        # Enhanced dropdown style
        self.style.configure('TCombobox',
                             padding=10,
                             font=('Arial', 12))

        self.os_dropdown = ttk.Combobox(self.header_frame,
                                        textvariable=self.os_var,
                                        values=["MacOS", "Windows"],
                                        state="readonly",
                                        font=('Arial', 18),  # Larger font
                                        width=20)
        self.os_dropdown.grid(row=2, column=0, pady=15)
        self.os_dropdown.bind('<<ComboboxSelected>>', self.on_os_select)

        # Create a divider for visual separation
        self.divider = ttk.Separator(self.main_frame, orient='horizontal')
        self.divider.grid(row=1, column=0, sticky="ew", pady=20)

        # Frame for buttons with increased padding for larger menu
        self.button_frame = ttk.Frame(self.main_frame, padding="10")
        self.button_frame.grid(row=2, column=0, pady=15)
        self.button_frame.grid_columnconfigure(0, weight=1)

        # Add a container frame to center-align buttons with a more prominent border
        self.button_container = ttk.Frame(self.button_frame, relief="groove", borderwidth=3)
        self.button_container.grid(row=0, column=0, padx=20)
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

        # Bind number keys 1-7 for direct selection
        self.root.bind('1', lambda event: self.button_click(0))
        self.root.bind('2', lambda event: self.button_click(1))
        self.root.bind('3', lambda event: self.button_click(2))
        self.root.bind('4', lambda event: self.button_click(3))
        self.root.bind('5', lambda event: self.button_click(4))
        self.root.bind('6', lambda event: self.button_click(5))
        self.root.bind('7', lambda event: self.button_click(6))

        # Also bind numpad keys
        self.root.bind('<KP_1>', lambda event: self.button_click(0))
        self.root.bind('<KP_2>', lambda event: self.button_click(1))
        self.root.bind('<KP_3>', lambda event: self.button_click(2))
        self.root.bind('<KP_4>', lambda event: self.button_click(3))
        self.root.bind('<KP_5>', lambda event: self.button_click(4))
        self.root.bind('<KP_6>', lambda event: self.button_click(5))
        self.root.bind('<KP_7>', lambda event: self.button_click(6))

    def on_os_select(self, event):
        # Clear existing buttons
        for button in self.buttons:
            button.destroy()
        self.buttons.clear()

        # Create new buttons based on OS selection
        # Changed to 7 buttons to include Exit option
        num_buttons = 7 if self.os_var.get() == "Windows" else 7

        for i in range(num_buttons):
            titles = self.windows_titles if self.os_var.get() == "Windows" else self.macos_titles

            btn = ttk.Button(self.button_container,
                             text=titles[i],
                             style='Responsive.TButton',
                             command=lambda x=i: self.button_click(x))

            btn.bind('<Enter>', lambda e, btn=btn: self.on_hover(e, btn))
            btn.bind('<Leave>', lambda e, btn=btn: self.on_leave(e, btn))

            # Add focus events for highlighting currently selected button
            btn.bind('<FocusIn>', lambda e, i=i: self.on_focus_in(i))
            btn.bind('<FocusOut>', self.on_focus_out)

            # Spacing between buttons - increased for larger menu
            btn.grid(row=i, column=0, pady=15, padx=30, sticky="ew")
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
                self.windows_ai_hardware_scan()

            elif button_num == 1:  # AI Software Scanning for Windows
                print("Starting Windows AI Software Scan...")
                self.windows_ai_software_scan()

            elif button_num == 2:  # AI Optimiser for Windows
                print("Starting Windows AI Optimiser...")
                self.windows_ai_optimiser()

            elif button_num == 3:  # Software Scanning for Windows
                print("Starting Windows Software Scan...")
                self.windows_software_scan()

            elif button_num == 4:  # Application Recommender for Windows
                print("Starting Windows Application Recommender...")
                AI_software_recommender.create_app_recommender()

            elif button_num == 5:  # Chat with AI Consultant for Windows
                print("Opening Windows AI Chat Console...")
                Chat_with_AI_agent.create_mistral_chat()

            elif button_num == 6:  # Exit
                print("Exiting Windows application...")
                self.root.quit()
                self.root.destroy()  # Force destroy the window

        elif current_os == "MacOS":
            if button_num == 0:  # AI Hardware Scanning for MacOS
                print("Starting MacOS AI Hardware Scan...")
                MacOS_Hardware_AI_Scan.show_macos_scan_window(self.root)

            elif button_num == 1:  # AI Software Scanning for MacOS
                print("Starting MacOS AI Software Scan...")
                MacOS_Software_AI_Scan.create_system_analyzer()

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

            elif button_num == 6:  # Exit
                print("Exiting MacOS application...")
                self.root.quit()
                self.root.destroy()  # Force destroy the window

    def on_hover(self, event, button):
        button.state(['active'])

    def on_leave(self, event, button):
        # Only remove active state if this button is not the focused one
        if self.buttons[self.focused_button_index] != button:
            button.state(['!active'])

    # Placeholder methods for Windows functionality
    def windows_ai_hardware_scan(self):
        print("Windows AI Hardware Scan not implemented yet")

    def windows_ai_software_scan(self):
        print("Windows AI Software Scan not implemented yet")

    def windows_ai_optimiser(self):
        print("Windows AI Optimiser not implemented yet")

    def windows_software_scan(self):
        print("Windows Software Scan not implemented yet")


# Add proper exit handler for the main window
def on_exit():
    print("Exiting application...")
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