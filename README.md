# SMART-Diagnose

An AI-powered system analysis and diagnostic tool for Windows and macOS.

🔗 **GitHub Repository**: https://github.com/valeri1383/Solent-Final-Project

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/valeri1383/Solent-Final-Project.git
   cd Solent-Final-Project
   ```

2. **Install Python 3.7+**
   - Download from [python.org](https://python.org)

3. **Install Required Libraries**
   ```bash
   pip install matplotlib pandas firebase-admin psutil pyttsx3 requests openai tkinter
   ```
   
   *Note: The application will auto-install missing libraries on first run*

## API Keys Setup
The application uses AI services that require API keys. You have two options:

Option 1: Use Default Keys (Quick Start)
The application includes working API keys for demonstration purposes. You can run it immediately without setup.

Option 2: Use Your Own Keys (Recommended)
For production use, replace the API keys in the following files:
1.	AI Services - Update these files with your API keys: 
	AI_optimiser.py - Line 25: Replace API_KEY = "your-openrouter-key"
	AI_security_scanner.py - Line 25: Replace API_KEY = "your-mistral-key"
	AI_software_recommender.py - Line 25: Replace API_KEY = "your-mistral-key"
	Chat_with_AI_agent.py - Line 22: Replace API_KEY = "your-mistral-key"

3.	Firebase Database - Replace database_key.json with your Firebase credentials: 
json
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key": "your-private-key",
  "client_email": "your-service-account@your-project.iam.gserviceaccount.com"
}
Get API Keys:
•	OpenRouter: https://openrouter.ai
•	Mistral: https://mistral.ai
•	Firebase: https://console.firebase.google.com
![image](https://github.com/user-attachments/assets/369edf32-d1bb-4b91-8463-f7d90fff2bf0)


## Quick Start

1. **Run the Application**
   ```bash
   python main.py
   ```

2. **Select Your OS**
   - Choose "Windows" or "MacOS" from the dropdown

3. **Available Features**
   - 🤖 AI Hardware Scanning
   - 🤖 AI Software Scanning  
   - 🔍 AI System Optimiser
   - ⚡ AI Security Scanner
   - 📱 AI App Recommender
   - 💬 Chat with AI Agent
   - 📊 Dashboard Visualisation

## Navigation

- **Keyboard Shortcuts**: Use number keys (1-8) or arrow keys + Enter
- **Mouse**: Click any button to launch features
- **Exit**: Press button 8 or close the window

## Requirements

- Python 3.7+
- Internet connection (for AI features)


