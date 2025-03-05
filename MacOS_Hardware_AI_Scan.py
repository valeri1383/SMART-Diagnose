import tkinter as tk
from tkinter import ttk
import openai
import psutil
import subprocess
from threading import Thread
import pyttsx3

def show_macos_scan_window(root):
    # Create new window
    scan_window = tk.Toplevel(root)
    scan_window.title("SMART-Diagnose")
    scan_window.geometry("1024x900")

    # Initialize text-to-speech engine
    engine = pyttsx3.init()

    # Create main frame
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
                              text="SMART-Diagnose Analysis",
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

    progress_label = ttk.Label(main_frame,
                              text="Analyzing...",
                              font=('Arial', 12))
    progress_label.grid(row=5, column=0, pady=(25, 8))

    progress = ttk.Progressbar(main_frame,
                              length=400,
                              mode='indeterminate')
    progress.grid(row=6, column=0)

    def get_macos_system_info():
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()

        try:
            os_version = subprocess.check_output(['sw_vers', '-productVersion']).decode().strip()
            uptime = subprocess.check_output(['uptime']).decode().strip()
            system_info = f"""
macOS Version: {os_version}
System Uptime: {uptime}
CPU Usage: {cpu_usage}%
Total Memory: {memory.total / (1024 ** 3):.2f} GB
Available Memory: {memory.available / (1024 ** 3):.2f} GB
Used Memory: {memory.used / (1024 ** 3):.2f} GB
Memory Usage: {memory.percent}%
"""
        except subprocess.CalledProcessError:
            system_info = f"""
CPU Usage: {cpu_usage}%
Total Memory: {memory.total / (1024 ** 3):.2f} GB
Available Memory: {memory.available / (1024 ** 3):.2f} GB
Used Memory: {memory.used / (1024 ** 3):.2f} GB
Memory Usage: {memory.percent}%
Note: Some macOS-specific information couldn't be retrieved
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

    def scan_complete():
        progress.stop()
        progress_label.config(text="Analysis Complete!")

    def run_scan():
        # Get system info
        system_report = get_macos_system_info()
        scan_window.after(0, update_system_info, system_report)

        # Get AI analysis
        user_prompt = f"Analyze the following system performance data and suggest optimizations. Speak as Personalised Technical bot:\n{system_report}"
        response = chat_with_mistral(user_prompt)

        # Update GUI with results
        scan_window.after(0, update_ai_analysis, response)
        scan_window.after(0, scan_complete)

    # Start progress bar and scan
    progress.start()
    Thread(target=run_scan).start()

    return scan_window