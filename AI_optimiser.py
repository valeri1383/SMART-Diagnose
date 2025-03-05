def create_ai_optimizer():
    """ This is AI optimizer application that is used in the main menu. """

    import tkinter as tk
    from tkinter import ttk
    import openai
    import psutil
    import threading
    import platform
    import pyttsx3
    import json
    import os

    class AIOptimizerApp:
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
            self.optimization_window = None

            # Thread state tracking variables
            self._thread_completed = False
            self._thread_result = None
            self._thread_error = None
            self._thread_status = None

            # AI API Key
            self.API_KEY = "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"

            # Configure main window
            self.main_frame = ttk.Frame(root, padding="20")
            self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

            root.grid_columnconfigure(0, weight=1)
            root.grid_rowconfigure(0, weight=1)

            # Create title
            title_label = ttk.Label(self.main_frame, text="SMART Performance Optimizer",
                                    font=('Arial', 16, 'bold'))
            title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

            # Create button to start optimization
            self.optimize_button = ttk.Button(self.main_frame, text="Optimize Your System",
                                              command=self.run_optimization)
            self.optimize_button.grid(row=1, column=0, sticky=tk.W, pady=10)

            # Create progress indicator
            self.status_var = tk.StringVar(value="Ready")
            self.status_label = ttk.Label(self.main_frame, textvariable=self.status_var)
            self.status_label.grid(row=1, column=1, sticky=tk.W, pady=10)

            # Create explanation text
            explanation = "This SMART tool analyzes your system resource usage and provides AI-powered recommendations to optimize performance and efficiency."
            explanation_label = ttk.Label(self.main_frame, text=explanation, wraplength=560)
            explanation_label.grid(row=2, column=0, columnspan=2, pady=10)

            # Create additional options frame
            options_frame = ttk.LabelFrame(self.main_frame, text="Optimization Options", padding=10)
            options_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

            # Add optimization type options
            self.opt_type = tk.StringVar(value="performance")
            ttk.Radiobutton(options_frame, text="Performance Focus", variable=self.opt_type,
                            value="performance").grid(row=0, column=0, sticky=tk.W, padx=5)
            ttk.Radiobutton(options_frame, text="Battery Focus", variable=self.opt_type,
                            value="battery").grid(row=0, column=1, sticky=tk.W, padx=5)
            ttk.Radiobutton(options_frame, text="Balanced", variable=self.opt_type,
                            value="balanced").grid(row=0, column=2, sticky=tk.W, padx=5)

        def get_system_metrics(self):
            """Collect system metrics for optimization analysis"""
            metrics = {}

            # System basics
            metrics["system"] = {
                "os": platform.system(),
                "version": platform.version(),
                "processor": platform.processor()
            }

            # CPU metrics
            metrics["cpu"] = {
                "usage_percent": psutil.cpu_percent(interval=1),
                "cores_physical": psutil.cpu_count(logical=False),
                "cores_logical": psutil.cpu_count(logical=True),
                "freq_current": psutil.cpu_freq().current if psutil.cpu_freq() else "N/A"
            }

            # Memory metrics
            memory = psutil.virtual_memory()
            metrics["memory"] = {
                "total_gb": round(memory.total / (1024 ** 3), 2),
                "available_gb": round(memory.available / (1024 ** 3), 2),
                "used_percent": memory.percent
            }

            # Disk metrics
            disk = psutil.disk_usage('/')
            metrics["disk"] = {
                "total_gb": round(disk.total / (1024 ** 3), 2),
                "free_gb": round(disk.free / (1024 ** 3), 2),
                "used_percent": disk.percent
            }

            # Network metrics
            network = psutil.net_io_counters()
            metrics["network"] = {
                "bytes_sent_mb": round(network.bytes_sent / (1024 ** 2), 2),
                "bytes_recv_mb": round(network.bytes_recv / (1024 ** 2), 2)
            }

            # Get top 5 processes by memory usage
            processes = []
            for proc in sorted(psutil.process_iter(['pid', 'name', 'memory_percent']),
                               key=lambda x: x.info['memory_percent'] or 0, reverse=True)[:5]:
                try:
                    processes.append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "memory_percent": round(proc.info['memory_percent'], 2)
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            metrics["top_processes"] = processes

            return metrics

        def chat_with_ai(self, prompt):
            """Sends prompt to AI and returns optimization recommendations"""
            try:
                client = openai.OpenAI(
                    base_url="https://openrouter.ai/api/v1",
                    api_key=self.API_KEY,
                    default_headers={
                        "HTTP-Referer": "https://your-app-domain.com",
                        "X-Title": "AI Optimizer"
                    },
                    timeout=30.0
                )

                response = client.chat.completions.create(
                    model="mistralai/mistral-7b-instruct:free",
                    messages=[{"role": "user", "content": prompt}]
                )

                result = response.choices[0].message.content
                return result
            except Exception as e:
                error_msg = f"Error connecting to AI service: {str(e)}"
                return error_msg

        def run_optimization(self):
            """Runs the system optimization analysis in a separate thread"""
            self.optimize_button.config(state="disabled")
            self.status_var.set("Collecting system metrics...")

            # Reset thread state variables
            self._thread_completed = False
            self._thread_result = None
            self._thread_error = None
            self._thread_status = None

            # Start analysis in a new thread
            threading.Thread(target=self._optimization_thread, daemon=True).start()

            # Start a periodic check for thread completion
            self.check_thread_status()

        def _optimization_thread(self):
            """Thread function to run optimization without blocking the UI"""
            try:
                # Get optimization type
                opt_type = self.opt_type.get()

                # Collect system metrics
                metrics = self.get_system_metrics()
                metrics_str = json.dumps(metrics, indent=2)

                # Update UI from the main thread - using a thread-safe approach
                # Instead of directly updating, we'll store the result and update in the main thread later
                self._thread_status = "Generating SMART optimization recommendations..."

                # Prepare prompt for AI analysis
                if opt_type == "performance":
                    focus_text = "maximizing performance and speed, even if it might use more resources"
                elif opt_type == "battery":
                    focus_text = "maximizing battery life and efficiency, prioritizing power saving"
                else:  # balanced
                    focus_text = "balancing performance and efficiency equally"

                user_prompt = f"""Analyze the following system metrics and provide optimization recommendations with a focus on {focus_text}:

                {metrics_str}

                Please provide and sound like personal AI agent:
                1. A brief analysis of the current system state
                2. 3-5 specific recommendations for optimization
                3. Expected performance improvements for each recommendation
                4. Any resource-intensive processes that should be addressed

                Format your response with clear headers and bullet points for easy reading.
                """

                # Send to AI and store result instead of using callback
                ai_response = self.chat_with_ai(user_prompt)
                self._thread_result = ai_response
                self._thread_completed = True

            except Exception as e:
                # Store error to be processed in the main thread
                self._thread_error = str(e)
                self._thread_completed = True

        def show_results(self, ai_response):
            """Shows the results window with system metrics and AI recommendations"""
            # Create new window with larger dimensions
            self.optimization_window = tk.Toplevel(self.root)
            self.optimization_window.title("SMART Optimization Results")
            self.optimization_window.geometry("1024x900")

            # Create main frame with increased padding
            main_frame = ttk.Frame(self.optimization_window, padding="30")
            main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

            # Configure grid weights
            self.optimization_window.grid_columnconfigure(0, weight=1)
            self.optimization_window.grid_rowconfigure(0, weight=1)
            main_frame.grid_columnconfigure(0, weight=1)

            # Create widgets with larger fonts and sizes
            info_label = ttk.Label(main_frame, text="System Metrics", font=('Arial', 20, 'bold'))
            info_label.grid(row=0, column=0, pady=(0, 20))

            # Get formatted metrics for display
            metrics = self.get_system_metrics()
            metrics_text = self.format_metrics_for_display(metrics)

            system_info = tk.Text(main_frame, height=13, width=100, font=('Courier', 16))
            system_info.grid(row=1, column=0, pady=(0, 25))
            system_info.insert(tk.END, metrics_text)
            system_info.config(state="disabled")

            analysis_label = ttk.Label(main_frame, text="SMART Optimization Recommendations", font=('Arial', 20, 'bold'))
            analysis_label.grid(row=2, column=0, pady=(0, 15))

            ai_analysis = tk.Text(main_frame, height=23, width=100, font=('Arial', 16))
            ai_analysis.grid(row=3, column=0)
            ai_analysis.insert(tk.END, ai_response)
            ai_analysis.config(state="disabled")

            # Add buttons frame
            buttons_frame = ttk.Frame(main_frame)
            buttons_frame.grid(row=4, column=0, pady=(15, 15))

            # Store active speech thread reference to be able to stop it
            self.active_speech_thread = None

            # Add speak buttons
            speak_sys_button = ttk.Button(
                buttons_frame,
                text="Read System Metrics",
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
            self.status_var.set("Optimization analysis complete")
            self.optimize_button.config(state="normal")

        def format_metrics_for_display(self, metrics):
            """Format the metrics dictionary into a readable string"""
            output = []

            # System info
            output.append("SYSTEM INFORMATION:")
            output.append(f"OS: {metrics['system']['os']} {metrics['system']['version']}")
            output.append(f"Processor: {metrics['system']['processor']}")
            output.append("")

            # CPU
            output.append("CPU:")
            output.append(f"Usage: {metrics['cpu']['usage_percent']}%")
            output.append(f"Physical cores: {metrics['cpu']['cores_physical']}")
            output.append(f"Logical cores: {metrics['cpu']['cores_logical']}")
            output.append(f"Current frequency: {metrics['cpu']['freq_current']} MHz")
            output.append("")

            # Memory
            output.append("MEMORY:")
            output.append(f"Total: {metrics['memory']['total_gb']} GB")
            output.append(f"Available: {metrics['memory']['available_gb']} GB")
            output.append(f"Used: {metrics['memory']['used_percent']}%")
            output.append("")

            # Disk
            output.append("DISK:")
            output.append(f"Total: {metrics['disk']['total_gb']} GB")
            output.append(f"Free: {metrics['disk']['free_gb']} GB")
            output.append(f"Used: {metrics['disk']['used_percent']}%")
            output.append("")

            # Top processes
            output.append("TOP MEMORY-INTENSIVE PROCESSES:")
            for proc in metrics['top_processes']:
                output.append(f"{proc['name']} (PID: {proc['pid']}): {proc['memory_percent']}%")

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
                    self.optimize_button.config(state="normal")
                # If we have results, show them
                elif self._thread_result:
                    self.show_results(self._thread_result)
                # Reset thread completion flag
                self._thread_completed = False
            else:
                # Check again after 100ms
                self.root.after(100, self.check_thread_status)

        def on_closing(self):
            """Handle window closing event"""
            self.stop_speaking()
            self.root.destroy()

        def return_to_main_menu(self):
            """Close the optimization window and return to main menu"""
            # First stop any ongoing speech
            self.stop_speaking()

            # Close the optimization window
            if self.optimization_window:
                self.optimization_window.destroy()
                self.optimization_window = None

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
    app = AIOptimizerApp(root, is_toplevel)

    # If running as standalone, start mainloop immediately
    if __name__ == "__main__":
        root.mainloop()

    # Return the root and app so the caller can manage them
    return root, app