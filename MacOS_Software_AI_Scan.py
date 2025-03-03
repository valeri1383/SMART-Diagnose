def create_system_analyzer():
    """
    Creates and returns a complete system analyzer application that can be imported and run
    from another file. Simply call this function to get the app running.

    Usage:
        from your_module import create_system_analyzer
        create_system_analyzer()
    """
    import tkinter as tk
    from tkinter import ttk
    import openai
    import psutil
    import subprocess
    import os
    import platform
    import pyttsx3
    import threading
    import time

    # Set your Mistral API Key
    API_KEY = "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"

    def get_software_info():
        """Collects software-related information"""
        software_info = []

        # Get OS information
        software_info.append(f"OS: {platform.system()} {platform.version()}")
        software_info.append(f"Python Version: {platform.python_version()}")

        # Get running processes
        process_count = len(list(psutil.process_iter()))
        software_info.append(f"Running Processes: {process_count}")

        # Check for recent application crashes (platform specific)
        if platform.system() == "Darwin":  # macOS
            try:
                # Check system logs
                proc = subprocess.Popen(
                    ["log", "show", "--predicate",
                     "subsystem == 'com.apple.launchd' AND eventMessage CONTAINS 'Failed'",
                     "--last", "1h"],
                    stdout=subprocess.PIPE
                )
                recent_errors = proc.communicate()[0].decode('utf-8', errors='ignore')
                software_info.append("Recent macOS Launch Failures (last hour):")
                software_info.append(recent_errors[:500] + "..." if len(recent_errors) > 500 else recent_errors)
            except Exception as e:
                software_info.append(f"Could not retrieve macOS logs: {str(e)}")

        # Check disk usage for software-related issues
        for partition in psutil.disk_partitions():
            if os.name == 'nt' and ('cdrom' in partition.opts or partition.fstype == ''):
                # Skip CD-ROM drives on Windows
                continue
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                if usage.percent > 90:
                    software_info.append(
                        f"Warning: Disk {partition.mountpoint} is {usage.percent}% full - this can cause software performance issues")
            except PermissionError:
                # Some mounted drives may require elevated permissions
                continue

        return "\n".join(software_info)

    def chat_with_mistral(prompt, callback=None):
        """Sends prompt to Mistral AI and returns a response"""
        try:
            client = openai.OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=API_KEY,
                default_headers={
                    "HTTP-Referer": "https://your-actual-site.com",
                    "X-Title": "Your Site Name"
                },
                timeout=30.0
            )

            response = client.chat.completions.create(
                model="mistralai/mistral-7b-instruct:free",
                messages=[{"role": "user", "content": prompt}]
            )

            result = response.choices[0].message.content
            if callback:
                callback(result)
            return result
        except Exception as e:
            error_msg = f"Error connecting to Mistral AI: {str(e)}"
            if callback:
                callback(error_msg)
            return error_msg

    def speak_text(text, engine):
        """Uses text-to-speech to read the given text"""
        try:
            engine.say(text)
            engine.runAndWait()
        except:
            # Handle any exceptions that might occur during speech
            pass

    class SystemAnalyzerApp:
        def __init__(self, root):
            self.root = root
            self.root.title("System Analyser")
            self.root.geometry("600x400")

            # Store reference to speech engine
            self.engine = pyttsx3.init()

            # Store reference to any child windows
            self.scan_window = None

            # Configure main window
            self.main_frame = ttk.Frame(root, padding="20")
            self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

            root.grid_columnconfigure(0, weight=1)
            root.grid_rowconfigure(0, weight=1)

            # Create title
            title_label = ttk.Label(self.main_frame, text="AI System Analyser",
                                    font=('Arial', 16, 'bold'))
            title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

            # Create button to start analysis
            self.analyze_button = ttk.Button(self.main_frame, text="Analyse Your System",
                                             command=self.run_analysis)
            self.analyze_button.grid(row=1, column=0, sticky=tk.W, pady=10)

            # Create progress indicator
            self.status_var = tk.StringVar(value="Ready")
            self.status_label = ttk.Label(self.main_frame, textvariable=self.status_var)
            self.status_label.grid(row=1, column=1, sticky=tk.W, pady=10)

            # Create explanation text
            explanation = "This tool collects system information and uses Personalised AI agent to analyse it for potential issues."
            explanation_label = ttk.Label(self.main_frame, text=explanation, wraplength=560)
            explanation_label.grid(row=2, column=0, columnspan=2, pady=10)

        def run_analysis(self):
            """Runs the system analysis in a separate thread"""
            self.analyze_button.config(state="disabled")
            self.status_var.set("Collecting system information...")

            # Start analysis in a new thread
            threading.Thread(target=self._analysis_thread, daemon=True).start()

        def _analysis_thread(self):
            """Thread function to run analysis without blocking the UI"""
            try:
                # Collect system information
                software_report = get_software_info()

                # Update UI from the main thread
                self.root.after(0, lambda: self.status_var.set("Analysing with advance AI agent..."))

                # Prepare prompt for AI analysis
                user_prompt = f"""Analyse the following software information and identify potential issues or optimizations:

                {software_report}

                Please focus on:
                1. Software conflicts or errors that may be causing performance issues
                2. Potential OS-level problems
                3. Application crash patterns if present
                4. Recommendations to improve software performance

                Provide a clear, structured analysis with bullet points for key issues.
                """

                # Send to Mistral AI
                chat_with_mistral(user_prompt, callback=self.show_results)

            except Exception as e:
                # Update UI to show error
                self.root.after(0, lambda: self.status_var.set(f"Error: {str(e)}"))
                self.root.after(0, lambda: self.analyze_button.config(state="normal"))

        def show_results(self, ai_response):
            """Shows the results window with system info and AI analysis"""
            # Create new window with larger dimensions
            self.scan_window = tk.Toplevel(self.root)
            self.scan_window.title("System Analysis Results")
            self.scan_window.geometry("1024x900")

            # Initialize text-to-speech engine
            engine = self.engine

            # Create main frame with increased padding
            main_frame = ttk.Frame(self.scan_window, padding="30")
            main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

            # Configure grid weights
            self.scan_window.grid_columnconfigure(0, weight=1)
            self.scan_window.grid_rowconfigure(0, weight=1)
            main_frame.grid_columnconfigure(0, weight=1)

            # Create widgets with larger fonts and sizes
            info_label = ttk.Label(main_frame, text="System Information", font=('Arial', 20, 'bold'))
            info_label.grid(row=0, column=0, pady=(0, 20))

            system_info = tk.Text(main_frame, height=13, width=100, font=('Courier', 16))
            system_info.grid(row=1, column=0, pady=(0, 25))
            system_info.insert(tk.END, get_software_info())
            system_info.config(state="disabled")

            analysis_label = ttk.Label(main_frame, text="AI Analysis", font=('Arial', 20, 'bold'))
            analysis_label.grid(row=2, column=0, pady=(0, 15))

            ai_analysis = tk.Text(main_frame, height=23, width=100, font=('Arial', 16))
            ai_analysis.grid(row=3, column=0)
            ai_analysis.insert(tk.END, ai_response)
            ai_analysis.config(state="disabled")

            # Add speaker buttons frame
            buttons_frame = ttk.Frame(main_frame)
            buttons_frame.grid(row=4, column=0, pady=(15, 15))

            # Store active speech thread reference to be able to stop it
            self.active_speech_thread = None

            # Add speak buttons
            speak_sys_button = ttk.Button(
                buttons_frame,
                text="Read System Info",
                command=lambda: self.start_speaking(system_info.get("1.0", tk.END))
            )
            speak_sys_button.grid(row=0, column=0, padx=10)

            speak_ai_button = ttk.Button(
                buttons_frame,
                text="Read AI Analysis",
                command=lambda: self.start_speaking(ai_analysis.get("1.0", tk.END))
            )
            speak_ai_button.grid(row=0, column=1, padx=10)

            # Changed from "Stop" to "Return to Main Menu"
            return_button = ttk.Button(
                buttons_frame,
                text="Return to Main Menu",
                command=self.return_to_main_menu
            )
            return_button.grid(row=0, column=2, padx=10)

            # Reset main window
            self.status_var.set("Analysis complete")
            self.analyze_button.config(state="normal")

        def start_speaking(self, text):
            """Start text-to-speech in a separate thread"""
            # Stop any ongoing speech
            self.stop_speaking()

            # Start new speech thread
            self.active_speech_thread = threading.Thread(
                target=speak_text,
                args=(text, self.engine),
                daemon=True
            )
            self.active_speech_thread.start()

        def stop_speaking(self):
            """Stop any ongoing speech"""
            try:
                self.engine.stop()
            except:
                # Handle any exceptions during speech stopping
                pass

        def return_to_main_menu(self):
            """Close the scan window and return to main menu"""
            # First stop any ongoing speech
            self.stop_speaking()

            # Close the scan window
            if self.scan_window:
                self.scan_window.destroy()
                self.scan_window = None

    # Modified so we can either run standalone or be imported
    if __name__ == "__main__":
        root = tk.Tk()
        app = SystemAnalyzerApp(root)
        root.mainloop()
    else:
        # When imported, just create and return the application
        root = tk.Tk()
        app = SystemAnalyzerApp(root)
        root.mainloop()