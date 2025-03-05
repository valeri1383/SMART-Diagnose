def create_security_scanner():
    """ Security scanner application that can be imported and run from another file. """

    import tkinter as tk
    from tkinter import ttk
    import openai
    import threading
    import platform
    import socket
    import subprocess
    import pyttsx3
    import os

    class SecurityScannerApp:
        def __init__(self, root, is_toplevel=False):
            self.root = root
            self.root.title("SMART-Diagnose")
            self.root.geometry("600x400")

            # Store whether this is a toplevel window
            self.is_toplevel = is_toplevel

            # Handle window close event differently based on window type
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

            # Store reference to speech engine
            self.engine = pyttsx3.init()

            # Store reference to any child windows
            self.scan_window = None

            # Thread state tracking variables
            self._thread_completed = False
            self._thread_result = None
            self._thread_error = None
            self._thread_status = None

            # AI API Key
            self.API_KEY = "brq0ubGwszOijmVjMlmTM5n07jU7CMbD"

            # Configure main window
            self.main_frame = ttk.Frame(root, padding="20")
            self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

            root.grid_columnconfigure(0, weight=1)
            root.grid_rowconfigure(0, weight=1)

            # Create title
            title_label = ttk.Label(self.main_frame, text="SMART Security Scanner",
                                    font=('Arial', 16, 'bold'))
            title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

            # Create button to start scan
            self.scan_button = ttk.Button(self.main_frame, text="Scan Your System",
                                          command=self.run_scan)
            self.scan_button.grid(row=1, column=0, sticky=tk.W, pady=10)

            # Create progress indicator
            self.status_var = tk.StringVar(value="Ready")
            self.status_label = ttk.Label(self.main_frame, textvariable=self.status_var)
            self.status_label.grid(row=1, column=1, sticky=tk.W, pady=10)

            # Create explanation text
            explanation = "This tool performs a security scan of your system and provides SMART powered recommendations to improve your security posture."
            explanation_label = ttk.Label(self.main_frame, text=explanation, wraplength=560)
            explanation_label.grid(row=2, column=0, columnspan=2, pady=10)

            # Create scan options frame
            options_frame = ttk.LabelFrame(self.main_frame, text="Scan Options", padding=10)
            options_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

            # Add scan type options
            self.scan_type = tk.StringVar(value="basic")
            ttk.Radiobutton(options_frame, text="Basic Scan", variable=self.scan_type,
                            value="basic").grid(row=0, column=0, sticky=tk.W, padx=5)
            ttk.Radiobutton(options_frame, text="Comprehensive Scan", variable=self.scan_type,
                            value="comprehensive").grid(row=0, column=1, sticky=tk.W, padx=5)

        def on_closing(self):
            """Handle window closing event"""
            self.stop_speaking()
            self.root.destroy()

        def run_scan(self):
            """Runs the security scan in a separate thread"""
            self.scan_button.config(state="disabled")
            self.status_var.set("Running SMART security scan...")

            # Reset thread state variables
            self._thread_completed = False
            self._thread_result = None
            self._thread_error = None
            self._thread_status = None

            # Start scan in a new thread
            threading.Thread(target=self._scan_thread, daemon=True).start()

            # Start a periodic check for thread completion
            self.check_thread_status()

        def check_thread_status(self):
            """Periodically checks if the background thread has completed"""
            # Update status message if available
            if self._thread_status:
                self.status_var.set(self._thread_status)
                self._thread_status = None

            if self._thread_completed:
                # If there was an error, show it
                if self._thread_error:
                    self.status_var.set(f"Error: {self._thread_error}")
                    self.scan_button.config(state="normal")
                # If we have results, show them
                elif self._thread_result:
                    self.show_results(self._thread_result)
                # Reset thread completion flag
                self._thread_completed = False
            else:
                # Check again after 100ms
                self.root.after(100, self.check_thread_status)

        def _scan_thread(self):
            """Thread function to run security scan without blocking the UI"""
            try:
                # Get scan type
                scan_type = self.scan_type.get()

                # Run security scan
                scan_results = self.scan_security(comprehensive=(scan_type == "comprehensive"))

                # Update UI from the main thread - using a thread-safe approach
                self._thread_status = "Getting SMART security recommendations..."

                # Get AI recommendations
                ai_response = self.get_ai_recommendations(scan_results)

                # Store results for processing in main thread
                self._thread_result = {
                    "scan_results": scan_results,
                    "ai_recommendations": ai_response
                }
                self._thread_completed = True

            except Exception as e:
                # Store error to be processed in the main thread
                self._thread_error = str(e)
                self._thread_completed = True

        def scan_security(self, comprehensive=False):
            """
            Perform a security scan of the system.
            """
            try:
                # Collect basic system info
                system = platform.system()
                results = {
                    "system": system,
                    "os_version": platform.version(),
                    "hostname": socket.gethostname(),
                    "issues": []
                }

                # Run basic security checks
                if system == "Darwin":  # macOS
                    self._check_macos_security(results, comprehensive)
                elif system == "Windows":
                    self._check_windows_security(results, comprehensive)

                return results

            except Exception as e:
                raise Exception(f"Error during security scan: {str(e)}")

        def _check_macos_security(self, results, comprehensive=False):
            """Check basic macOS security settings"""
            # Check firewall status
            try:
                # Try using a more user-friendly approach that doesn't require admin privileges
                fw_cmd = "defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo 'unknown'"
                fw_status = subprocess.check_output(fw_cmd, shell=True).decode('utf-8').strip()

                if fw_status == "unknown":
                    results["firewall_enabled"] = "unknown"
                else:
                    results["firewall_enabled"] = fw_status != "0"

                    if fw_status == "0":
                        results["issues"].append({
                            "type": "firewall",
                            "issue": "System firewall is disabled",
                            "fix": "Enable the firewall in System Preferences > Security & Privacy"
                        })
            except:
                results["firewall_enabled"] = "unknown"
                results["issues"].append({
                    "type": "permissions",
                    "issue": "Could not determine firewall status due to permission restrictions",
                    "fix": "Run this application with admin privileges to check firewall status"
                })

            # Check FileVault (disk encryption)
            try:
                # Use a more robust command that works without admin privileges
                fv_cmd = "fdesetup status 2>/dev/null || echo 'unknown'"
                fv_output = subprocess.check_output(fv_cmd, shell=True).decode('utf-8').strip()

                if fv_output == "unknown":
                    results["disk_encryption_enabled"] = "unknown"
                else:
                    filevault_enabled = "FileVault is On" in fv_output

                    results["disk_encryption_enabled"] = filevault_enabled

                    if not filevault_enabled:
                        results["issues"].append({
                            "type": "encryption",
                            "issue": "FileVault disk encryption is not enabled",
                            "fix": "Enable FileVault in System Preferences > Security & Privacy > FileVault"
                        })
            except:
                results["disk_encryption_enabled"] = "unknown"
                results["issues"].append({
                    "type": "permissions",
                    "issue": "Could not determine FileVault status due to permission restrictions",
                    "fix": "Run this application with admin privileges to check encryption status"
                })

            # Check FileVault (disk encryption)
            try:
                fv_cmd = "fdesetup status"
                fv_output = subprocess.check_output(fv_cmd, shell=True).decode('utf-8').strip()
                filevault_enabled = "FileVault is On" in fv_output

                results["disk_encryption_enabled"] = filevault_enabled

                if not filevault_enabled:
                    results["issues"].append({
                        "type": "encryption",
                        "issue": "FileVault disk encryption is not enabled",
                        "fix": "Enable FileVault in System Preferences > Security & Privacy > FileVault"
                    })
            except:
                results["disk_encryption_enabled"] = "unknown"

            # Check for system updates
            try:
                # Use a non-privileged command to check for updates
                update_cmd = "softwareupdate -l 2>&1 | grep -v 'No new software available'"
                update_output = subprocess.check_output(update_cmd, shell=True, stderr=subprocess.STDOUT).decode(
                    'utf-8', errors='ignore').strip()

                if update_output and "Finding available software" not in update_output:
                    results["issues"].append({
                        "type": "updates",
                        "issue": "System software updates may be available",
                        "fix": "Check for updates in System Preferences > Software Update"
                    })
            except:
                pass

            # Additional comprehensive checks
            if comprehensive:
                # Check Gatekeeper status - use a safer approach
                try:
                    gk_cmd = "spctl --status 2>/dev/null || echo 'unknown'"
                    gk_output = subprocess.check_output(gk_cmd, shell=True).decode('utf-8', errors='ignore').strip()

                    if gk_output == "unknown":
                        results["gatekeeper_enabled"] = "unknown"
                    else:
                        gatekeeper_enabled = "assessments enabled" in gk_output.lower()
                        results["gatekeeper_enabled"] = gatekeeper_enabled

                        if not gatekeeper_enabled:
                            results["issues"].append({
                                "type": "protection",
                                "issue": "Gatekeeper protection is disabled",
                                "fix": "Enable Gatekeeper using: sudo spctl --master-enable"
                            })
                except:
                    results["gatekeeper_enabled"] = "unknown"

                # Check SIP (System Integrity Protection) - use a safer approach
                try:
                    sip_cmd = "csrutil status 2>/dev/null || echo 'unknown'"
                    sip_output = subprocess.check_output(sip_cmd, shell=True).decode('utf-8', errors='ignore').strip()

                    if sip_output == "unknown":
                        results["sip_enabled"] = "unknown"
                    else:
                        sip_enabled = "enabled" in sip_output.lower()
                        results["sip_enabled"] = sip_enabled

                        if not sip_enabled:
                            results["issues"].append({
                                "type": "protection",
                                "issue": "System Integrity Protection (SIP) is disabled",
                                "fix": "Enable SIP by booting into Recovery Mode and running: csrutil enable"
                            })
                except:
                    results["sip_enabled"] = "unknown"

        def _check_windows_security(self, results, comprehensive=False):
            """Simple Windows security checks"""
            # Basic checks
            results["issues"].append({
                "type": "platform",
                "issue": "Windows security scan is limited in this version",
                "fix": "Consider running Windows Security for a comprehensive scan"
            })

            # Attempt to check Windows Defender status
            try:
                cmd = "powershell -command \"Get-MpComputerStatus | Select-Object AntivirusEnabled\""
                defender_output = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
                defender_enabled = "True" in defender_output

                results["antivirus_enabled"] = defender_enabled

                if not defender_enabled:
                    results["issues"].append({
                        "type": "antivirus",
                        "issue": "Windows Defender antivirus is not enabled",
                        "fix": "Enable Windows Defender in Windows Security settings"
                    })
            except:
                results["antivirus_enabled"] = "unknown"



        def get_ai_recommendations(self, scan_results):
            """
            Get AI-powered security recommendations.
            """
            try:
                # Format issues for the prompt
                issues_str = ""
                for issue in scan_results.get("issues", []):
                    issues_str += f"- {issue['issue']}\n"

                if not issues_str:
                    issues_str = "- No security issues detected\n"

                # Create the prompt
                prompt = f"""
                Give me security recommendations for my computer. Sound like AI custom agent. Here's my system information:

                Operating System: {scan_results['system']} {scan_results['os_version']}
                Hostname: {scan_results['hostname']}

                Security issues found:
                {issues_str}

                Firewall enabled: {scan_results.get('firewall_enabled', 'unknown')}
                Disk encryption enabled: {scan_results.get('disk_encryption_enabled', 'unknown')}
                Antivirus enabled: {scan_results.get('antivirus_enabled', 'unknown')}
                Gatekeeper enabled: {scan_results.get('gatekeeper_enabled', 'unknown')}
                SIP enabled: {scan_results.get('sip_enabled', 'unknown')}

                Please provide:
                1. A brief security assessment (1-2 sentences)
                2. Top 3 simple recommendations to improve my security

                Keep your response organized with clear headers and bullet points.
                """

                # Call Mistral API directly
                import requests

                headers = {
                    "Authorization": f"Bearer {self.API_KEY}",
                    "Content-Type": "application/json"
                }

                data = {
                    "model": "mistral-tiny",
                    "messages": [{"role": "user", "content": prompt}]
                }

                response = requests.post(
                    "https://api.mistral.ai/v1/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=30
                )

                if response.status_code != 200:
                    return f"Error: API returned status code {response.status_code} - {response.text}"

                result = response.json()
                return result['choices'][0]['message']['content']
            except Exception as e:
                return f"Error generating security recommendations: {str(e)}"

        def show_results(self, results):
            """Shows the results window with scan results and AI recommendations"""
            # Create new window with larger dimensions
            self.scan_window = tk.Toplevel(self.root)
            self.scan_window.title("Security Scan Results")
            self.scan_window.geometry("1024x900")

            # Create main frame
            main_frame = ttk.Frame(self.scan_window, padding="30")
            main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

            # Configure grid weights
            self.scan_window.grid_columnconfigure(0, weight=1)
            self.scan_window.grid_rowconfigure(0, weight=1)
            main_frame.grid_columnconfigure(0, weight=1)

            # Create widgets
            info_label = ttk.Label(main_frame, text="SMART Security Scan", font=('Arial', 20, 'bold'))
            info_label.grid(row=0, column=0, pady=(0, 20))

            # Get formatted scan results for display
            scan_results = results["scan_results"]
            scan_text = self.format_scan_results_for_display(scan_results)

            system_info = tk.Text(main_frame, height=13, width=100, font=('Courier', 16))
            system_info.grid(row=1, column=0, pady=(0, 25))
            system_info.insert(tk.END, scan_text)
            system_info.config(state="disabled")

            analysis_label = ttk.Label(main_frame, text="SMART Security Recommendations", font=('Arial', 20, 'bold'))
            analysis_label.grid(row=2, column=0, pady=(0, 15))

            ai_analysis = tk.Text(main_frame, height=20, width=100, font=('Arial', 16))
            ai_analysis.grid(row=3, column=0)
            ai_analysis.insert(tk.END, results["ai_recommendations"])
            ai_analysis.config(state="disabled")

            # Add buttons frame
            buttons_frame = ttk.Frame(main_frame)
            buttons_frame.grid(row=4, column=0, pady=(15, 15))

            # Store active speech thread reference to be able to stop it
            self.active_speech_thread = None

            # Add speak buttons
            speak_sys_button = ttk.Button(
                buttons_frame,
                text="Read Scan Results",
                command=lambda: self.start_speaking(system_info.get("1.0", tk.END))
            )
            speak_sys_button.grid(row=0, column=0, padx=10)

            speak_ai_button = ttk.Button(
                buttons_frame,
                text="Read Recommendations",
                command=lambda: self.start_speaking(ai_analysis.get("1.0", tk.END))
            )
            speak_ai_button.grid(row=0, column=1, padx=10)

            # Add return button
            return_button = ttk.Button(
                buttons_frame,
                text="Return to Main Menu",
                command=self.return_to_main_menu
            )
            return_button.grid(row=0, column=2, padx=10)

            # Reset main window
            self.status_var.set("Security scan complete")
            self.scan_button.config(state="normal")

        def format_scan_results_for_display(self, scan_results):
            """Format the scan results dictionary into a readable string"""
            output = []

            # System info
            output.append("SYSTEM INFORMATION:")
            output.append(f"OS: {scan_results['system']} {scan_results['os_version']}")
            output.append(f"Hostname: {scan_results['hostname']}")
            output.append("")

            # Security settings
            output.append("SECURITY SETTINGS:")

            # Firewall
            if 'firewall_enabled' in scan_results:
                status = "Enabled" if scan_results['firewall_enabled'] == True else "Disabled" if scan_results[
                                                                                                      'firewall_enabled'] == False else "Unknown"
                output.append(f"Firewall: {status}")

            # Disk encryption
            if 'disk_encryption_enabled' in scan_results:
                status = "Enabled" if scan_results['disk_encryption_enabled'] == True else "Disabled" if scan_results[
                                                                                                             'disk_encryption_enabled'] == False else "Unknown"
                output.append(f"Disk Encryption: {status}")

            # Antivirus
            if 'antivirus_enabled' in scan_results:
                status = "Enabled" if scan_results['antivirus_enabled'] == True else "Disabled" if scan_results[
                                                                                                       'antivirus_enabled'] == False else "Unknown"
                output.append(f"Antivirus: {status}")

            # Gatekeeper (macOS)
            if 'gatekeeper_enabled' in scan_results:
                status = "Enabled" if scan_results['gatekeeper_enabled'] == True else "Disabled" if scan_results[
                                                                                                        'gatekeeper_enabled'] == False else "Unknown"
                output.append(f"Gatekeeper: {status}")

            # SIP (macOS)
            if 'sip_enabled' in scan_results:
                status = "Enabled" if scan_results['sip_enabled'] == True else "Disabled" if scan_results[
                                                                                                 'sip_enabled'] == False else "Unknown"
                output.append(f"System Integrity Protection: {status}")

            output.append("")

            # Security issues
            output.append("SECURITY ISSUES:")
            if scan_results["issues"]:
                for issue in scan_results["issues"]:
                    output.append(f"- {issue['issue']}")
                    output.append(f"  Fix: {issue['fix']}")
            else:
                output.append("No security issues found!")

            return "\n".join(output)

        def start_speaking(self, text):
            """Start text-to-speech in a separate thread"""
            # Stop any ongoing speech
            self.stop_speaking()

            # Start new speech thread
            self.active_speech_thread = threading.Thread(
                target=self.speak_text,
                args=(text,),
                daemon=True
            )
            self.active_speech_thread.start()

        def speak_text(self, text):
            """Uses text-to-speech to read the given text"""
            try:
                self.engine.say(text)
                self.engine.runAndWait()
            except:
                # Handle any exceptions that might occur during speech
                pass

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

    # Create the application with a Toplevel window instead of Tk
    if __name__ == "__main__":
        # If running standalone, use Tk as the root
        root = tk.Tk()
        is_toplevel = False
    else:
        # If imported, create a temporary hidden root and use Toplevel
        # This allows the window to be closed without affecting the parent app
        temp_root = tk.Tk()
        temp_root.withdraw()  # Hide the temporary root
        root = tk.Toplevel()
        is_toplevel = True

    # Pass the is_toplevel flag to the app
    app = SecurityScannerApp(root, is_toplevel)

    # If running as standalone, start mainloop immediately
    if __name__ == "__main__":
        root.mainloop()

    # Return the root and app so the caller can manage them
    return root, app

