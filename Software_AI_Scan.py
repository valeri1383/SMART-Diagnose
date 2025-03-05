def create_system_analyzer():
    """ System analyzer function that can be imported and run from another file. """

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
    import datetime
    import socket
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import firestore

    # Set Mistral API Key
    API_KEY = "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"

    # Initialize Firebase if not already initialized
    def init_firebase():
        try:
            # Check if already initialized
            firebase_admin.get_app()
        except ValueError:
            # Not initialized yet, use the provided credentials
            cred = credentials.Certificate({
                "type": "service_account",
                "project_id": "diagnostic-app-e1587",
                "private_key_id": "b90d2679828c37b3d5bcc22b4d6b90f8119ced9d",
                "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7vWOdXTmPyWDY\nEk4Cic8PoVUnPcLJU5/6AJd9c1BnuElJWaxABXwGaMaoTv6G7jGxPUt/35f+84PQ\n1HaCFFI3kgn+SnU9zibgldqIU3bt9jjfQBPu0VHPNSFzFEv9zBTKo74XIEMUZ88B\n4H7RE2CGwxv6klwJzwUF78iPJhziuWmbWUd+hNxGX17zGHO1DfJaNnqazTJnJ7ZZ\nLVYhLCzdn/NBiPa6pQwEqLmuc0oG3Et7FIR20lu27uOhFMu8DHEUvWimbiP0YgId\nSBhJGOdi9V9lwmhey4OB4988EbQX/H/J+dsbsdDUVv6FR+I6RMptYJGrrm/eyR5D\n8Yt7MNQxAgMBAAECggEACihzLV6P8MG6pbZH1kdSlsvp6Zej5HTL4SELEVSd8x67\niGZ7tXMWhNpCdXTgvLhCpA5m+WJFvRu79B6q0tr6n9sdA09QDKoM3HX/PwUVGEcM\nSLgU3AUjYgzD5JAilHboYRZ/AI1UU9RSFQ3qjrF3tZL0/pfQtw8mfG2+8k/jnDjI\nTnmUlOO7xCC5CWY1VTqdaCxyUFvhyn6rYUyMZyD2L+Mrp8uXFEekIZ6WSOjyxa4E\nwVQ3iYaKROycFAFXpvRQoa8d50k3A9YRYszpWabj0rjMUOT7Eb9vJOrvONJWq1M/\nx8hdM1q8dmVCGg6HaocB5K481qkmVmHtB0RzlyAcYQKBgQDdJv0ymIqSG5bOi0zA\nmkqSCm0L3hfn3PIAksF1MtdAmctJPhSGuQ3n6d5TEPnLjm6djJF3fl66qcyCfGxa\n8YqD1vtWwJpIjGfPR93ny1OCTLwtgNnOSJrSZ1XPApr+sd/LrdV42r6D/k4jqXPY\nEg/oqqJQGAoIn6ddB6Sii8DbhQKBgQDZUpS/9tktcaSHAuxHSYx2fZGE6i0fVzUk\nO/VbiiwcSO5A+UH7o4qxqIcfd9g8S5xuA8+ofroa9Bd6XeCh3I7zmCnFMtmcYIkN\n87b+NB2nY5IQIStP0ZHM8fnpQd60aZVVBzIHmS0RjiZGMD/vg23igVNxl9SOjc3o\nbEZZu5+nvQKBgQCL3kHbAyD44VwSy4VCdxLcpJ1tGQ0ThujDtg2Gux3qbJpme03u\nGxIRcBc9gAoMVMve9u11nsX41rVSfbDmH8fUNF6H8o5hffOV5EUTecQaL8AAI3Md\nhUvt8I8TuvkeRo9dOVc+9VHzFx6CbYSnzlyjcW/wqhOGersWGmRkrXDPJQKBgF/C\nocUMspnxr3vGb/Lhl8FGh263+XYL6WC0AuN5OQKlqEZ9DvQhFiY+inv1RRUchCt+\nBmzKmprx376Ny0PHej4gWJeKVpUvfHTnZUUSFdcCawQseXdMcyCJp4N/APEibSjw\naL0sY82Og5L+A844bZ0XO3ucWY8PMSIvQ7iakjlJAoGAPSAtuC7ijKYT1GeRPaWa\nxbyzadk3eTMuo1FU6YhTtEKxPVLAs3kfQqwncxeDz4jUHN4M3JY/armKAeDhbnGE\nWPYDqSddcjTGNVz7gZcFIzoU+Ispnugm1n6CaIUYPHSi5hOgLS6VcdvrP8VY7be4\nFkyxIplYqIxCzok0WFgbsWA=\n-----END PRIVATE KEY-----\n",
                "client_email": "firebase-adminsdk-fbsvc@diagnostic-app-e1587.iam.gserviceaccount.com",
                "client_id": "105288815211730348964",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40diagnostic-app-e1587.iam.gserviceaccount.com",
                "universe_domain": "googleapis.com"
            })
            firebase_admin.initialize_app(cred)

        # Return Firestore client and results collection reference
        db = firestore.client()
        return db, db.collection('test_results')

    def get_device_id():
        """Get a unique identifier for the current device"""
        try:
            return socket.gethostname()
        except:
            return "unknown_device"

    def record_test_start(test_name, test_type):
        """Record the start of a test in Firestore and return the document ID"""
        # Initialize Firebase
        _, results_ref = init_firebase()

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        test_data = {
            "timestamp": timestamp,
            "test_name": test_name,
            "test_type": test_type,
            "status": "Running",
            "device_id": get_device_id(),
            "details": {
                "start_time": timestamp,
                "os": platform.system()
            }
        }

        # Add to Firestore and get document ID
        doc_ref = results_ref.add(test_data)
        return doc_ref[1].id  # Returns the document ID

    def update_test_status(test_id, status, system_info=None, ai_analysis=None):
        """Update the test result in Firestore with the final status and details"""
        # Initialize Firebase
        _, results_ref = init_firebase()

        end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Extract key metrics if available
        process_count = None

        if system_info:
            for line in system_info.split('\n'):
                if 'Running Processes' in line:
                    try:
                        process_count = int(line.split(':')[1].strip())
                    except:
                        pass

        # Create details object
        details = {
            "end_time": end_time,
            "process_count": process_count
        }

        # Add summary of AI analysis if available
        if ai_analysis:
            details["summary"] = ai_analysis[:500] + "..." if len(ai_analysis) > 500 else ai_analysis

        # Update Firestore document
        results_ref.document(test_id).update({
            "status": status,
            "details": details
        })

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
            self.root.title("SMART-Diagnose")
            self.root.geometry("600x400")

            # Store reference to speech engine
            self.engine = pyttsx3.init()

            # Store reference to any child windows
            self.scan_window = None

            # Store test ID for Firestore tracking
            self.current_test_id = None

            # Store system info and AI analysis
            self.system_info = None
            self.ai_analysis = None

            # Configure main window
            self.main_frame = ttk.Frame(root, padding="20")
            self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

            root.grid_columnconfigure(0, weight=1)
            root.grid_rowconfigure(0, weight=1)

            # Create title
            title_label = ttk.Label(self.main_frame, text="SMART-Diagnose",
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
            explanation = "This tool collects system information and uses out SMART-Diagnose Personalised AI agent to analyse it for potential issues."
            explanation_label = ttk.Label(self.main_frame, text=explanation, wraplength=560)
            explanation_label.grid(row=2, column=0, columnspan=2, pady=10)

        def run_analysis(self):
            """Runs the system analysis in a separate thread"""
            self.analyze_button.config(state="disabled")
            self.status_var.set("Collecting system information...")

            # Record test start in Firestore
            self.current_test_id = record_test_start("AI Software Scanning", "Software")

            # Start analysis in a new thread
            threading.Thread(target=self._analysis_thread, daemon=True).start()

        def _analysis_thread(self):
            """Thread function to run analysis without blocking the UI"""
            try:
                # Collect system information
                self.system_info = get_software_info()

                # Update UI from the main thread
                self.root.after(0, lambda: self.status_var.set("Analysing with SMART-Diagnose agent..."))

                # Prepare prompt for AI analysis
                user_prompt = f"""Analyse the following software information and identify potential issues or optimizations:

                {self.system_info}

                Please focus on:
                1. Software conflicts or errors that may be causing performance issues
                2. Potential OS-level problems
                3. Application crash patterns if present
                

                Provide a clear, structured analysis with bullet points for key issues.
                """

                # Send to Mistral AI
                self.ai_analysis = chat_with_mistral(user_prompt)

                # Update test status in Firestore as successful
                update_test_status(
                    self.current_test_id,
                    status="Passed",
                    system_info=self.system_info,
                    ai_analysis=self.ai_analysis
                )

                # Show results in UI
                self.root.after(0, lambda: self.show_results(self.ai_analysis))

            except Exception as e:
                error_msg = str(e)
                # Update UI to show error
                self.root.after(0, lambda: self.status_var.set(f"Error: {error_msg}"))
                self.root.after(0, lambda: self.analyze_button.config(state="normal"))

                # Update test status in Firestore as failed
                update_test_status(
                    self.current_test_id,
                    status="Failed",
                    system_info=self.system_info,
                    ai_analysis=f"Error: {error_msg}"
                )

        def show_results(self, ai_response):
            """Shows the results window with system info and AI analysis"""
            # Create new window with larger dimensions
            self.scan_window = tk.Toplevel(self.root)
            self.scan_window.title("SMART-Diagnose")
            self.scan_window.geometry("1024x900")

            # Initialize text-to-speech engine
            engine = self.engine

            # Create main frame
            main_frame = ttk.Frame(self.scan_window, padding="30")
            main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

            # Configure grid weights
            self.scan_window.grid_columnconfigure(0, weight=1)
            self.scan_window.grid_rowconfigure(0, weight=1)
            main_frame.grid_columnconfigure(0, weight=1)

            # Create widgets
            info_label = ttk.Label(main_frame, text="System Information", font=('Arial', 20, 'bold'))
            info_label.grid(row=0, column=0, pady=(0, 20))

            system_info_widget = tk.Text(main_frame, height=13, width=100, font=('Courier', 16))
            system_info_widget.grid(row=1, column=0, pady=(0, 25))
            system_info_widget.insert(tk.END, self.system_info)
            system_info_widget.config(state="disabled")

            analysis_label = ttk.Label(main_frame, text="SMART-Diagnose Analys", font=('Arial', 20, 'bold'))
            analysis_label.grid(row=2, column=0, pady=(0, 15))

            ai_analysis_widget = tk.Text(main_frame, height=23, width=100, font=('Arial', 16))
            ai_analysis_widget.grid(row=3, column=0)
            ai_analysis_widget.insert(tk.END, ai_response)
            ai_analysis_widget.config(state="disabled")

            # Add test result status frame
            status_frame = ttk.Frame(main_frame)
            status_frame.grid(row=4, column=0, pady=(10, 10))

            result_label = ttk.Label(status_frame, text="Test Result:", font=('Arial', 12, 'bold'))
            result_label.grid(row=0, column=0, padx=5)

            status_var = tk.StringVar(value="Passed")  # Default to passed

            # Create status indicator
            status_indicator = ttk.Label(
                status_frame,
                textvariable=status_var,
                font=('Arial', 12, 'bold'),
                foreground="green"
            )
            status_indicator.grid(row=0, column=1, padx=5)

            # Add buttons to mark test status
            pass_btn = ttk.Button(
                status_frame,
                text="Mark as Passed",
                command=lambda: self.update_test_result("Passed", status_var, status_indicator)
            )
            pass_btn.grid(row=0, column=2, padx=5)

            warning_btn = ttk.Button(
                status_frame,
                text="Mark as Warning",
                command=lambda: self.update_test_result("Warning", status_var, status_indicator)
            )
            warning_btn.grid(row=0, column=3, padx=5)

            fail_btn = ttk.Button(
                status_frame,
                text="Mark as Failed",
                command=lambda: self.update_test_result("Failed", status_var, status_indicator)
            )
            fail_btn.grid(row=0, column=4, padx=5)

            # Add speaker buttons frame
            buttons_frame = ttk.Frame(main_frame)
            buttons_frame.grid(row=5, column=0, pady=(15, 15))

            # Store active speech thread reference to be able to stop it
            self.active_speech_thread = None

            # Add speak buttons
            speak_sys_button = ttk.Button(
                buttons_frame,
                text="Read System Info",
                command=lambda: self.start_speaking(system_info_widget.get("1.0", tk.END))
            )
            speak_sys_button.grid(row=0, column=0, padx=10)

            speak_ai_button = ttk.Button(
                buttons_frame,
                text="Read AI Analysis",
                command=lambda: self.start_speaking(ai_analysis_widget.get("1.0", tk.END))
            )
            speak_ai_button.grid(row=0, column=1, padx=10)


            return_button = ttk.Button(
                buttons_frame,
                text="Return to Main Menu",
                command=self.return_to_main_menu
            )
            return_button.grid(row=0, column=2, padx=10)

            # Reset main window
            self.status_var.set("Analysis complete")
            self.analyze_button.config(state="normal")

        def update_test_result(self, status, status_var, status_indicator):
            """Update the test result in Firestore and UI"""
            # Update the status label
            status_var.set(status)

            # Update color based on status
            if status == "Passed":
                status_indicator.config(foreground="green")
            elif status == "Warning":
                status_indicator.config(foreground="orange")
            else:  # Failed
                status_indicator.config(foreground="red")

            # Update status in Firestore
            if self.current_test_id:
                update_test_status(
                    self.current_test_id,
                    status=status,
                    system_info=self.system_info,
                    ai_analysis=self.ai_analysis
                )

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
        root = tk.Tk()
        app = SystemAnalyzerApp(root)
        root.mainloop()