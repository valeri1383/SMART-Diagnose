def create_mistral_chat(parent_root=None):
    """
    Creates a Mistral AI Chat interface that can be integrated with a parent application.
    Uses thread-safe mechanisms for UI updates.

    Args:
        parent_root: The parent Tk root window. If None, creates its own window.
    """
    import tkinter as tk
    from tkinter import ttk, scrolledtext
    import requests
    from datetime import datetime
    import json
    from tkinter import messagebox
    import threading
    import queue
    import time

    # Store UI update requests in a queue to handle thread safety
    ui_update_queue = queue.Queue()

    # Check if we should create our own root or use parent
    if parent_root is None:
        # Standalone mode - create our own root
        chat_window = tk.Tk()
        chat_window.title("Personalised AI Agent")
        chat_window.geometry("800x600")
        is_standalone = True
    else:
        # Integrated mode - create a toplevel window
        chat_window = tk.Toplevel(parent_root)
        chat_window.title("Personalised AI Agent")
        chat_window.geometry("800x600")
        chat_window.transient(parent_root)  # Set as transient to parent
        is_standalone = False

    chat_window.configure(bg='#1e1e1e')

    # Initialize tracking variables
    chat_active = threading.Event()
    chat_active.set()  # Mark the chat as active

    # Variable to track if Shift key is pressed (for multi-line input)
    shift_pressed = False

    # API Configuration
    API_KEY = "brq0ubGwszOijmVjMlmTM5n07jU7CMbD"
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    # Configure style
    style = ttk.Style()
    style.configure('Modern.TFrame', background='#1e1e1e')
    style.configure('Send.TButton', padding=10, font=('Helvetica', 10))

    # Create main container
    main_frame = ttk.Frame(chat_window, style='Modern.TFrame')
    main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Create chat display area
    chat_frame = ttk.Frame(main_frame, style='Modern.TFrame')
    chat_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

    chat_display = scrolledtext.ScrolledText(
        chat_frame,
        wrap=tk.WORD,
        font=('Helvetica', 11),
        background='#2d2d2d',
        foreground='#ffffff',
        padx=10,
        pady=10,
        height=20
    )
    chat_display.pack(fill=tk.BOTH, expand=True)

    # Create input area
    input_frame = ttk.Frame(main_frame, style='Modern.TFrame')
    input_frame.pack(fill=tk.X, pady=(0, 5))

    message_input = tk.Text(
        input_frame,
        font=('Helvetica', 11),
        height=3,
        background='gray30',
        foreground='#ffffff',
        insertbackground='#ffffff'
    )
    message_input.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 10))

    # Create send button (defining it here but packing later)
    send_button = ttk.Button(
        input_frame,
        text="Send",
        style='Send.TButton'
    )

    # Create bottom frame for controls
    bottom_frame = ttk.Frame(main_frame, style='Modern.TFrame')
    bottom_frame.pack(fill=tk.X, pady=(10, 0))

    def append_message(role, content):
        timestamp = datetime.now().strftime("%H:%M")
        chat_display.configure(state='normal')

        if role == "user":
            chat_display.insert(tk.END, f"\n[{timestamp}] You:\n", "user_header")
            chat_display.tag_configure("user_header", foreground="#007AFF")
        else:
            chat_display.insert(tk.END, f"\n[{timestamp}] AI Agent:\n", "assistant_header")
            chat_display.tag_configure("assistant_header", foreground="#FF3B30")

        chat_display.insert(tk.END, f"{content}\n")
        chat_display.configure(state='disabled')
        chat_display.see(tk.END)

    def enable_input():
        message_input.configure(state='normal')
        send_button.configure(state='normal')
        message_input.focus()

    def process_message(message):
        try:
            if not chat_active.is_set():
                return

            data = {
                "model": "mistral-tiny",
                "messages": [{"role": "user", "content": message}]
            }

            response = requests.post(
                "https://api.mistral.ai/v1/chat/completions",
                headers=headers,
                json=data
            )
            response.raise_for_status()

            result = response.json()
            assistant_message = result['choices'][0]['message']['content']

            # Queue the UI update instead of directly calling after()
            if chat_active.is_set():
                ui_update_queue.put(("append_message", ("assistant", assistant_message)))
                ui_update_queue.put(("enable_input", ()))

        except Exception as e:
            if chat_active.is_set():
                ui_update_queue.put(("show_error", (f"An error occurred: {str(e)}",)))
                ui_update_queue.put(("enable_input", ()))

    def send_message(event=None):
        message = message_input.get("1.0", tk.END).strip()
        if not message:
            return

        # Clear input field
        message_input.delete("1.0", tk.END)

        # Disable input while processing
        message_input.configure(state='disabled')
        send_button.configure(state='disabled')

        # Display user message
        append_message("user", message)

        # Create and start message thread
        thread = threading.Thread(target=process_message, args=(message,))
        thread.daemon = True
        thread.start()

        return "break"  # Prevents the default Enter behavior (new line)

    # Handle key press events for tracking Shift key state
    def on_key_press(event):
        nonlocal shift_pressed
        if event.keysym == 'Shift_L' or event.keysym == 'Shift_R':
            shift_pressed = True

    # Handle key release events for tracking Shift key state
    def on_key_release(event):
        nonlocal shift_pressed
        if event.keysym == 'Shift_L' or event.keysym == 'Shift_R':
            shift_pressed = False

    # Handle Enter key specifically
    def on_enter_press(event):
        if shift_pressed:
            # If Shift is pressed with Enter, insert a newline as normal
            return  # Allow default behavior
        else:
            # If Enter alone is pressed, send the message
            return send_message(event)

    # Set send_button command now that the function is defined
    send_button.configure(command=send_message)
    send_button.pack(side=tk.RIGHT)

    # Add return to main menu button if in integrated mode
    if not is_standalone:
        return_button = ttk.Button(
            bottom_frame,
            text="Return to Main Menu",
            command=lambda: close_chat()
        )
        return_button.pack(side=tk.RIGHT)

    # Key bindings for message input
    message_input.bind('<Control-Return>', send_message)  # Keep Ctrl+Enter
    message_input.bind('<Return>', on_enter_press)  # Add Enter key binding
    message_input.bind('<KeyPress>', on_key_press)  # Track key presses
    message_input.bind('<KeyRelease>', on_key_release)  # Track key releases

    # Function to show error messageboxes
    def show_error(message):
        messagebox.showerror("Error", message)

    # Configure grid
    chat_window.grid_rowconfigure(0, weight=1)
    chat_window.grid_columnconfigure(0, weight=1)

    # Track the after ID so we can cancel it
    ui_queue_after_id = None

    # Clean up function
    def close_chat():
        nonlocal ui_queue_after_id
        chat_active.clear()  # Signal threads to stop

        # Cancel the pending after call if it exists
        if ui_queue_after_id is not None:
            chat_window.after_cancel(ui_queue_after_id)
            ui_queue_after_id = None

        chat_window.destroy()

    # Clean up on window close
    chat_window.protocol("WM_DELETE_WINDOW", close_chat)

    # Process the UI update queue periodically
    def process_ui_queue():
        nonlocal ui_queue_after_id

        try:
            while not ui_update_queue.empty():
                action, args = ui_update_queue.get_nowait()
                if action == "append_message":
                    append_message(*args)
                elif action == "enable_input":
                    enable_input()
                elif action == "show_error":
                    show_error(*args)
        except Exception as e:
            print(f"Error processing UI updates: {e}")

        # Schedule the next check if the chat is still active
        if chat_active.is_set():
            try:
                # Store the after ID so we can cancel it if needed
                ui_queue_after_id = chat_window.after(100, process_ui_queue)
            except tk.TclError:
                # Window might have been destroyed
                chat_active.clear()
                print("Window no longer exists, stopping UI updates")

    # Start the UI update process
    ui_queue_after_id = chat_window.after(100, process_ui_queue)

    # Display welcome message as a Personalised AI agent
    welcome_message = (
        "Hello! I'm your Personalised AI Agent. I'm here to assist you with any "
        "questions, information, or tasks you need help with. My advanced AI capabilities "
        "allow me to understand your unique needs and provide tailored responses.\n\n"
        "How can I help you today?\n\n"
        "TIP: Press Enter to send a message. Use Shift+Enter for multi-line messages."
    )
    append_message("assistant", welcome_message)

    # Return the window for standalone mode to run mainloop
    if is_standalone:
        chat_window.mainloop()

    return chat_window


# Example of how to use:
if __name__ == "__main__":
    # Standalone mode
    create_mistral_chat()