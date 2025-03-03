def create_app_recommender():
    """
    Creates and returns a complete app recommender application that can be imported and run
    from another file. Simply call this function to get the app running.

    Usage:
        from your_module import create_app_recommender
        create_app_recommender()
    """
    import tkinter as tk
    from tkinter import ttk
    import subprocess
    import platform
    import os
    import threading
    import pyttsx3
    import requests
    import json

    class AppRecommenderApp:
        def __init__(self, root, is_toplevel=False):
            self.root = root
            self.root.title("App Recommender")
            self.root.geometry("600x400")

            # Store whether this is a toplevel window
            self.is_toplevel = is_toplevel

            # Handle window close event differently based on window type
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

            # Store reference to speech engine
            self.engine = pyttsx3.init()

            # Store reference to any child windows
            self.results_window = None

            # Thread state tracking variables
            self._thread_completed = False
            self._thread_result = None
            self._thread_error = None
            self._thread_status = None

            # API Key - replace with your own
            self.API_KEY = "brq0ubGwszOijmVjMlmTM5n07jU7CMbD"

            # Configure main window
            self.main_frame = ttk.Frame(root, padding="20")
            self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

            root.grid_columnconfigure(0, weight=1)
            root.grid_rowconfigure(0, weight=1)

            # Create title
            title_label = ttk.Label(self.main_frame, text="App Recommender",
                                    font=('Arial', 16, 'bold'))
            title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

            # Create button to start scan
            self.scan_button = ttk.Button(self.main_frame, text="Scan Apps & Get Recommendations",
                                          command=self.run_scan)
            self.scan_button.grid(row=1, column=0, sticky=tk.W, pady=10)

            # Create progress indicator
            self.status_var = tk.StringVar(value="Ready")
            self.status_label = ttk.Label(self.main_frame, textvariable=self.status_var)
            self.status_label.grid(row=1, column=1, sticky=tk.W, pady=10)

            # Create explanation text
            explanation = "This tool scans your installed applications and uses AI to recommend new software that would complement your current setup."
            explanation_label = ttk.Label(self.main_frame, text=explanation, wraplength=560)
            explanation_label.grid(row=2, column=0, columnspan=2, pady=10)

            # Create scan options frame
            options_frame = ttk.LabelFrame(self.main_frame, text="Recommendation Options", padding=10)
            options_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

            # Add recommendation type options
            self.rec_type = tk.StringVar(value="all")
            ttk.Radiobutton(options_frame, text="All App Types", variable=self.rec_type,
                            value="all").grid(row=0, column=0, sticky=tk.W, padx=5)
            ttk.Radiobutton(options_frame, text="Productivity Focus", variable=self.rec_type,
                            value="productivity").grid(row=0, column=1, sticky=tk.W, padx=5)
            ttk.Radiobutton(options_frame, text="Creative Focus", variable=self.rec_type,
                            value="creative").grid(row=0, column=2, sticky=tk.W, padx=5)

        def on_closing(self):
            """Handle window closing event"""
            self.stop_speaking()
            self.root.destroy()

        def run_scan(self):
            """Runs the app scan in a separate thread"""
            self.scan_button.config(state="disabled")
            self.status_var.set("Scanning installed applications...")

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
            """Thread function to scan apps without blocking the UI"""
            try:
                # Get recommendation type
                rec_type = self.rec_type.get()

                # Scan installed apps
                scan_results = self.scan_installed_apps()

                # Update thread status
                self._thread_status = "Getting AI app recommendations..."

                # Get AI recommendations
                ai_response = self.get_app_recommendations(scan_results, rec_type)

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

        def scan_installed_apps(self):
            """
            Scan for installed applications.

            Returns:
                dict: Information about installed applications
            """
            try:
                # Collect basic system info
                system = platform.system()
                results = {
                    "system": system,
                    "os_version": platform.version(),
                    "installed_apps": [],
                    "app_categories": {}
                }

                # Scan for installed applications based on OS
                if system == "Darwin":  # macOS
                    self._scan_macos_apps(results)
                elif system == "Windows":
                    self._scan_windows_apps(results)
                elif system == "Linux":
                    self._scan_linux_apps(results)

                # Categorize apps
                self._categorize_apps(results)

                return results

            except Exception as e:
                raise Exception(f"Error scanning apps: {str(e)}")

        def _scan_macos_apps(self, results):
            """Scan for installed applications on macOS"""
            try:
                # Get applications in the Applications folder
                apps_cmd = "ls -1 /Applications"
                apps_output = subprocess.check_output(apps_cmd, shell=True).decode('utf-8')

                # Process the list
                apps_list = apps_output.strip().split('\n')

                # Filter for .app files
                for app in apps_list:
                    if app.endswith('.app'):
                        app_name = app.replace('.app', '')
                        results["installed_apps"].append({
                            "name": app_name,
                            "path": f"/Applications/{app}"
                        })

                # Also check user Applications folder
                user_apps_path = os.path.expanduser("~/Applications")
                if os.path.exists(user_apps_path):
                    user_apps_cmd = f"ls -1 {user_apps_path}"
                    try:
                        user_apps_output = subprocess.check_output(user_apps_cmd, shell=True).decode('utf-8')
                        user_apps_list = user_apps_output.strip().split('\n')

                        # Filter for .app files
                        for app in user_apps_list:
                            if app and app.endswith('.app'):
                                app_name = app.replace('.app', '')
                                results["installed_apps"].append({
                                    "name": app_name,
                                    "path": f"~/Applications/{app}"
                                })
                    except:
                        pass
            except Exception as e:
                raise Exception(f"Error scanning macOS apps: {str(e)}")

        def _scan_windows_apps(self, results):
            """Scan for installed applications on Windows"""
            try:
                # Use PowerShell to get installed apps
                cmd = "powershell -command \"Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, InstallLocation | Where-Object { $_.DisplayName -ne $null } | ConvertTo-Json\""
                try:
                    apps_output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
                    apps_list = json.loads(apps_output)

                    # Handle case where only one app is returned (not in a list)
                    if not isinstance(apps_list, list):
                        apps_list = [apps_list]

                    for app in apps_list:
                        if "DisplayName" in app and app["DisplayName"]:
                            results["installed_apps"].append({
                                "name": app["DisplayName"],
                                "path": app.get("InstallLocation", "Unknown")
                            })
                except:
                    # Fallback to simple example if PowerShell command fails
                    results["installed_apps"].append(
                        {"name": "Example Windows App", "path": "C:\\Program Files\\Example"})
                    results["note"] = "Windows app scanning limited in this version"
            except Exception as e:
                raise Exception(f"Error scanning Windows apps: {str(e)}")

        def _scan_linux_apps(self, results):
            """Scan for installed applications on Linux"""
            try:
                # Try using the 'apt' package manager
                cmd = "apt list --installed 2>/dev/null | grep -v 'Listing...' | head -n 50 || echo ''"
                try:
                    apps_output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
                    if apps_output.strip():
                        apps_list = apps_output.strip().split('\n')
                        for app_line in apps_list:
                            if app_line:
                                # Format is typically name/source,version [arch]
                                app_name = app_line.split('/')[0] if '/' in app_line else app_line
                                results["installed_apps"].append({
                                    "name": app_name,
                                    "path": "/usr/bin/" + app_name.lower()
                                })
                except:
                    # Fallback
                    results["installed_apps"].append({"name": "Example Linux App", "path": "/usr/bin/example"})
                    results["note"] = "Linux app scanning limited in this version"
            except Exception as e:
                raise Exception(f"Error scanning Linux apps: {str(e)}")

        def _categorize_apps(self, results):
            """Categorize installed applications"""
            # Define some common app categories and example apps in each
            categories = {
                "Productivity": ["Microsoft", "Office", "Word", "Excel", "PowerPoint", "Pages", "Numbers",
                                 "Keynote", "Outlook", "Evernote", "OneNote", "Notion", "Slack", "Teams",
                                 "Zoom", "Google", "Docs", "Sheets", "Calendar"],

                "Development": ["Xcode", "Visual Studio", "Code", "Eclipse", "IntelliJ", "PyCharm",
                                "WebStorm", "Atom", "Sublime", "Terminal", "iTerm", "GitHub", "Git",
                                "Android Studio", "Unity", "Docker", "Postman"],

                "Design": ["Photoshop", "Illustrator", "InDesign", "Sketch", "Figma", "Adobe",
                           "Lightroom", "GIMP", "Inkscape", "Affinity", "Designer", "Photo", "Canva"],

                "Media": ["iTunes", "Music", "Spotify", "VLC", "QuickTime", "iMovie", "Final Cut",
                          "Premier", "After Effects", "Netflix", "Hulu", "Disney", "YouTube"],

                "Games": ["Steam", "Epic Games", "Battle.net", "Minecraft", "League of Legends",
                          "Fortnite", "Roblox", "Origin", "Uplay"],

                "Utilities": ["Finder", "Explorer", "Chrome", "Safari", "Firefox", "Edge", "Opera",
                              "Brave", "CleanMyMac", "CCleaner", "Time Machine", "Backup", "Antivirus",
                              "Security", "Calculator", "Calendar"]
            }

            # Count apps in each category
            category_counts = {category: 0 for category in categories}

            # Assign apps to categories
            for app in results["installed_apps"]:
                app_name = app["name"]

                for category, keywords in categories.items():
                    if any(keyword.lower() in app_name.lower() for keyword in keywords):
                        if category not in results["app_categories"]:
                            results["app_categories"][category] = []

                        results["app_categories"][category].append(app_name)
                        category_counts[category] += 1
                        break

            # Determine user's primary categories
            results["primary_categories"] = sorted(
                category_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:3]

        def get_app_recommendations(self, scan_results, rec_type="all"):
            """
            Get AI-powered app recommendations based on installed software.

            Args:
                scan_results (dict): Results from scan_installed_apps()
                rec_type (str): Type of recommendations to focus on

            Returns:
                str: AI-generated app recommendations
            """
            try:
                # Format installed apps for the prompt
                installed_apps_str = ", ".join([app["name"] for app in scan_results.get("installed_apps", [])][:20])

                # Format app categories
                categories_str = ""
                for category, apps in scan_results.get("app_categories", {}).items():
                    categories_str += f"- {category}: {', '.join(apps[:5])}\n"

                if not categories_str:
                    categories_str = "- No clear categories detected\n"

                # Primary categories
                primary_categories = [cat for cat, count in scan_results.get("primary_categories", [])]
                primary_categories_str = ", ".join(primary_categories) if primary_categories else "None detected"

                # Adjust focus based on recommendation type
                focus_str = ""
                if rec_type == "productivity":
                    focus_str = "Focus specifically on productivity tools, task management, note-taking, communication, and workflow enhancement apps."
                elif rec_type == "creative":
                    focus_str = "Focus specifically on creative tools, design software, media editing, content creation, and artistic apps."

                # Create the prompt
                prompt = f"""
                I need recommendations for useful applications based on my current software.

                My system: {scan_results['system']} {scan_results['os_version']}

                Some of my installed applications: {installed_apps_str}

                My app categories:
                {categories_str}

                My primary app categories: {primary_categories_str}

                {focus_str}

                Please provide:
                1. A brief assessment of my current software profile
                2. 5 specific app recommendations that would complement my existing software
                3. For each recommendation, include:
                   - App name
                   - Brief description (1 sentence)
                   - Why it would be useful for me based on my current apps

                Focus on apps that are well-reviewed, preferably free or with free tiers.
                """

                # Call Mistral API
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
                return f"Error generating app recommendations: {str(e)}"

        def show_results(self, results):
            """Shows the results window with installed apps and AI recommendations"""
            # Create new window with larger dimensions
            self.results_window = tk.Toplevel(self.root)
            self.results_window.title("App Recommendations")
            self.results_window.geometry("1024x900")

            # Create main frame with increased padding
            main_frame = ttk.Frame(self.results_window, padding="30")
            main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

            # Configure grid weights
            self.results_window.grid_columnconfigure(0, weight=1)
            self.results_window.grid_rowconfigure(0, weight=1)
            main_frame.grid_columnconfigure(0, weight=1)

            # Create widgets with larger fonts and sizes
            info_label = ttk.Label(main_frame, text="Installed Applications", font=('Arial', 20, 'bold'))
            info_label.grid(row=0, column=0, pady=(0, 20))

            # Get formatted installed apps for display
            scan_results = results["scan_results"]
            apps_text = self.format_apps_for_display(scan_results)

            installed_apps = tk.Text(main_frame, height=13, width=100, font=('Courier', 16))
            installed_apps.grid(row=1, column=0, pady=(0, 25))
            installed_apps.insert(tk.END, apps_text)
            installed_apps.config(state="disabled")

            analysis_label = ttk.Label(main_frame, text="AI App Recommendations", font=('Arial', 20, 'bold'))
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
            speak_apps_button = ttk.Button(
                buttons_frame,
                text="Read App Summary",
                command=lambda: self.start_speaking(installed_apps.get("1.0", tk.END))
            )
            speak_apps_button.grid(row=0, column=0, padx=10)

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
            self.status_var.set("App scanning complete")
            self.scan_button.config(state="normal")

        def format_apps_for_display(self, scan_results):
            """Format the installed apps information into a readable string"""
            output = []

            # System info
            output.append("SYSTEM INFORMATION:")
            output.append(f"OS: {scan_results['system']} {scan_results['os_version']}")
            output.append("")

            # App stats
            output.append(f"INSTALLED APPS: {len(scan_results['installed_apps'])}")
            output.append("")

            # App categories
            output.append("APPLICATION CATEGORIES:")
            if scan_results.get("app_categories"):
                for category, apps in scan_results.get("app_categories", {}).items():
                    output.append(f"- {category}: {len(apps)} apps")
                    # Show up to 5 example apps in each category
                    examples = ", ".join(apps[:5])
                    output.append(f"  Examples: {examples}")
            else:
                output.append("No categories detected")
            output.append("")

            # Primary categories
            output.append("PRIMARY CATEGORIES:")
            if scan_results.get("primary_categories"):
                for category, count in scan_results.get("primary_categories", []):
                    output.append(f"- {category}: {count} apps")
            else:
                output.append("No primary categories detected")

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
            """Close the results window and return to main menu"""
            # First stop any ongoing speech
            self.stop_speaking()

            # Close the results window
            if self.results_window:
                self.results_window.destroy()
                self.results_window = None

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
    app = AppRecommenderApp(root, is_toplevel)

    # If running as standalone, start mainloop immediately
    if __name__ == "__main__":
        root.mainloop()

    # Return the root and app so the caller can manage them
    return root, app

