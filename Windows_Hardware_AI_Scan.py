import tkinter as tk
from tkinter import ttk
import openai
import psutil
import subprocess
from threading import Thread
import pyttsx3
import datetime
import socket
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
import platform
import os
import queue


def create_windows_diagnostic_app():
    """ Creates the Windows diagnostic application with all functionality. """

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

    def show_windows_scan_window(root):
        # Initialize Firebase
        init_firebase()

        # Get Firestore client
        db = firestore.client()

        # Reference to results collection
        results_ref = db.collection('test_results')

        # Create a test result record with "Running" status
        test_id = record_test_start(results_ref)

        # Create new window with larger dimensions
        scan_window = tk.Toplevel(root)
        scan_window.title("System Analysis Results")
        scan_window.geometry("1024x900")

        # Initialize text-to-speech engine
        engine = pyttsx3.init()

        # Create main frame with increased padding
        main_frame = ttk.Frame(scan_window, padding="30")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        scan_window.grid_columnconfigure(0, weight=1)
        scan_window.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        # Create widgets
        info_label = ttk.Label(main_frame,
                               text="System Information",
                               font=('Arial', 20, 'bold'))
        info_label.grid(row=0, column=0, pady=(0, 20))

        system_info = tk.Text(main_frame,
                              height=13,
                              width=100,
                              font=('Courier', 16))
        system_info.grid(row=1, column=0, pady=(0, 25))

        analysis_label = ttk.Label(main_frame,
                                   text="AI Analysis",
                                   font=('Arial', 20, 'bold'))
        analysis_label.grid(row=2, column=0, pady=(0, 15))

        ai_analysis = tk.Text(main_frame,
                              height=23,
                              width=100,
                              font=('Arial', 16))
        ai_analysis.grid(row=3, column=0)

        # Add speaker buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=4, column=0, pady=(15, 15))

        def speak_system_info():
            text = system_info.get("1.0", tk.END).strip()
            if text:
                Thread(target=lambda: engine.say(text) or engine.runAndWait()).start()

        def speak_analysis():
            text = ai_analysis.get("1.0", tk.END).strip()
            if text:
                Thread(target=lambda: engine.say(text) or engine.runAndWait()).start()

        # Add speaker buttons with icons
        system_speaker_btn = ttk.Button(buttons_frame,
                                        text="🔊 Sound for System Info",
                                        command=speak_system_info)
        system_speaker_btn.grid(row=0, column=0, padx=10)

        analysis_speaker_btn = ttk.Button(buttons_frame,
                                          text="🔊 Sound for Analysis",
                                          command=speak_analysis)
        analysis_speaker_btn.grid(row=0, column=1, padx=10)

        # Add buttons for test status
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=5, column=0, pady=(15, 15))

        result_var = tk.StringVar(value="Result: Running...")
        result_label = ttk.Label(status_frame, textvariable=result_var, font=('Arial', 12, 'bold'))
        result_label.grid(row=0, column=0, padx=5)

        pass_btn = ttk.Button(
            status_frame,
            text="Mark as Passed",
            command=lambda: update_test_status(results_ref, test_id, "Passed", system_info.get("1.0", tk.END),
                                               ai_analysis.get("1.0", tk.END), result_var)
        )
        pass_btn.grid(row=0, column=1, padx=5)

        warning_btn = ttk.Button(
            status_frame,
            text="Mark as Warning",
            command=lambda: update_test_status(results_ref, test_id, "Warning", system_info.get("1.0", tk.END),
                                               ai_analysis.get("1.0", tk.END), result_var)
        )
        warning_btn.grid(row=0, column=2, padx=5)

        fail_btn = ttk.Button(
            status_frame,
            text="Mark as Failed",
            command=lambda: update_test_status(results_ref, test_id, "Failed", system_info.get("1.0", tk.END),
                                               ai_analysis.get("1.0", tk.END), result_var)
        )
        fail_btn.grid(row=0, column=3, padx=5)

        progress_label = ttk.Label(main_frame,
                                   text="Analyzing...",
                                   font=('Arial', 12))
        progress_label.grid(row=6, column=0, pady=(25, 8))

        progress = ttk.Progressbar(main_frame,
                                   length=400,
                                   mode='indeterminate')
        progress.grid(row=7, column=0)

        # Create a message queue for thread-safe communication
        message_queue = queue.Queue()

        def get_windows_system_info():
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()

            try:
                # Windows-specific information
                os_version = platform.platform()

                # Get system uptime
                boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
                now = datetime.datetime.now()
                uptime = now - boot_time
                days, seconds = uptime.days, uptime.seconds
                hours = seconds // 3600
                minutes = (seconds % 3600) // 60
                uptime_str = f"{days} days, {hours} hours, {minutes} minutes"

                # Get disk information
                disk = psutil.disk_usage('/')

                system_info = f"""
Windows Version: {os_version}
System Uptime: {uptime_str}
CPU Usage: {cpu_usage}%
Total Memory: {memory.total / (1024 ** 3):.2f} GB
Available Memory: {memory.available / (1024 ** 3):.2f} GB
Used Memory: {memory.used / (1024 ** 3):.2f} GB
Memory Usage: {memory.percent}%
Disk Total: {disk.total / (1024 ** 3):.2f} GB
Disk Used: {disk.used / (1024 ** 3):.2f} GB
Disk Free: {disk.free / (1024 ** 3):.2f} GB
Disk Usage: {disk.percent}%
"""
            except Exception as e:
                system_info = f"""
CPU Usage: {cpu_usage}%
Total Memory: {memory.total / (1024 ** 3):.2f} GB
Available Memory: {memory.available / (1024 ** 3):.2f} GB
Used Memory: {memory.used / (1024 ** 3):.2f} GB
Memory Usage: {memory.percent}%
Note: Some Windows-specific information couldn't be retrieved. Error: {str(e)}
"""
            return system_info.strip()

        def chat_with_mistral(prompt):
            API_KEY = "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"
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
            return response.choices[0].message.content

        def update_system_info(info):
            system_info.delete(1.0, tk.END)
            system_info.insert(tk.END, info)

        def update_ai_analysis(analysis):
            ai_analysis.delete(1.0, tk.END)
            ai_analysis.insert(tk.END, analysis)

        def scan_complete(system_report, ai_response):
            progress.stop()
            progress_label.config(text="Analysis Complete!")

            # Automatically mark test as Passed if analysis completed successfully
            if ai_response and len(ai_response) > 10:
                update_test_status(
                    results_ref,
                    test_id,
                    "Passed",
                    system_report,
                    ai_response,
                    result_var,
                    auto_update=True
                )
            else:
                update_test_status(
                    results_ref,
                    test_id,
                    "Warning",
                    system_report,
                    "AI analysis may be incomplete",
                    result_var,
                    auto_update=True
                )

        # Process messages from the queue and update UI on the main thread
        def process_message_queue():
            try:
                while not message_queue.empty():
                    message = message_queue.get_nowait()
                    message_type = message.get("type")

                    if message_type == "system_info":
                        update_system_info(message.get("data"))
                    elif message_type == "ai_analysis":
                        update_ai_analysis(message.get("data"))
                    elif message_type == "scan_complete":
                        scan_complete(message.get("system_report"), message.get("ai_response"))
            except Exception as e:
                print(f"Error processing messages: {e}")

            # Schedule to check queue again
            scan_window.after(100, process_message_queue)

        def run_scan():
            try:
                # Get system info
                system_report = get_windows_system_info()
                # Put system info in queue instead of directly updating UI
                message_queue.put({"type": "system_info", "data": system_report})

                # Get AI analysis
                user_prompt = f"Analyze the following system performance data and suggest optimizations. Speak as Personalised Technical bot:\n{system_report}"

                try:
                    response = chat_with_mistral(user_prompt)
                    # Put AI response in queue instead of directly updating UI
                    message_queue.put({"type": "ai_analysis", "data": response})
                    message_queue.put(
                        {"type": "scan_complete", "system_report": system_report, "ai_response": response})
                except Exception as e:
                    error_message = f"Error during analysis: {str(e)}"
                    message_queue.put({"type": "ai_analysis", "data": error_message})
                    message_queue.put(
                        {"type": "scan_complete", "system_report": system_report, "ai_response": error_message})

                    # Update test status to Failed in case of error
                    update_test_status(
                        results_ref,
                        test_id,
                        "Failed",
                        system_report,
                        error_message,
                        result_var,
                        auto_update=True
                    )
            except Exception as e:
                print(f"Error in run_scan: {e}")

        # Start the message queue processor
        scan_window.after(100, process_message_queue)

        # Start progress bar and scan
        progress.start()
        Thread(target=run_scan).start()

        return scan_window

    def get_device_id():
        """Get a unique identifier for the current device"""
        try:
            # Try to get hostname as device ID
            return socket.gethostname()
        except:
            return "unknown_device"

    def record_test_start(results_ref):
        """Record the start of a test in Firestore and return the document ID"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        test_data = {
            "timestamp": timestamp,
            "test_name": "AI Hardware Scanning",
            "test_type": "Hardware",
            "status": "Running",
            "device_id": get_device_id(),
            "details": {
                "start_time": timestamp,
                "os": "Windows" if platform.system() == "Windows" else platform.system()
            }
        }

        # Add to Firestore and get document ID
        doc_ref = results_ref.add(test_data)
        return doc_ref[1].id  # Returns the document ID

    def update_test_status(results_ref, test_id, status, system_info, ai_analysis, result_var, auto_update=False):
        """Update the test result in Firestore with the final status and details"""
        end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Extract key metrics from system_info
        cpu_usage = None
        memory_usage = None
        disk_usage = None

        for line in system_info.split('\n'):
            if 'CPU Usage' in line:
                try:
                    cpu_usage = float(line.split('%')[0].split(':')[1].strip())
                except:
                    pass
            elif 'Memory Usage' in line:
                try:
                    memory_usage = float(line.split('%')[0].split(':')[1].strip())
                except:
                    pass
            elif 'Disk Usage' in line:
                try:
                    disk_usage = float(line.split('%')[0].split(':')[1].strip())
                except:
                    pass

        # Create details object
        details = {
            "end_time": end_time,
            "cpu_usage": cpu_usage,
            "memory_usage": memory_usage,
            "disk_usage": disk_usage,
            "summary": ai_analysis[:500] + "..." if len(ai_analysis) > 500 else ai_analysis
        }

        # Update Firestore document
        results_ref.document(test_id).update({
            "status": status,
            "details": details
        })

        # Update the result label
        result_var.set(f"Result: {status}")

        # If this is an automatic update, add a note
        if auto_update:
            result_var.set(f"Result: {status} (Auto)")

    # Return a dictionary of functions that can be used
    return {
        "show_scan_window": show_windows_scan_window,
        "init_firebase": init_firebase,
        "get_device_id": get_device_id
    }


def create_windows_diagnostic_app_standalone():
    """
    A simple wrapper function that creates the Windows diagnostic app
    and returns a function that can be called to show the diagnostic window.
    This is the main function to import in other modules.
    """
    # Get the diagnostic app functions
    diagnostic_app = create_windows_diagnostic_app()

    # Return the main function that consumers will use
    def show_windows_diagnostic(parent_window=None):
        """
        Shows the Windows diagnostic window.

        Args:
            parent_window: The parent tkinter window. If None, a new Tk root will be created.

        Returns:
            The scan window object.
        """
        if parent_window is None:
            # Create a new root window if none provided
            root = tk.Tk()
            root.title("Windows Diagnostic")
            root.withdraw()  # Hide the root window

            # Show the scan window
            scan_window = diagnostic_app["show_scan_window"](root)

            # Configure the scan window to destroy the root when closed
            scan_window.protocol("WM_DELETE_WINDOW", lambda: (scan_window.destroy(), root.destroy()))

            return scan_window
        else:
            # Use the provided parent window
            return diagnostic_app["show_scan_window"](parent_window)

    # Return the function
    return show_windows_diagnostic


# This is the function you should import in other modules
windows_hardware_scan = create_windows_diagnostic_app_standalone()

# Example of usage when run directly
if __name__ == "__main__":
    # Create a simple root window
    root = tk.Tk()
    root.title("Windows Diagnostic App")
    root.geometry("300x100")

    # Add button to open scan window
    start_button = ttk.Button(
        root,
        text="Start System Scan",
        command=lambda: windows_hardware_scan(root)
    )
    start_button.pack(pady=30)

    root.mainloop()