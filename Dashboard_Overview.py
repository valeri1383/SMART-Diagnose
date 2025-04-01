import tkinter as tk
from tkinter import ttk
import matplotlib

matplotlib.use('TkAgg')  # Must be before importing pyplot
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
from datetime import datetime, timedelta
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
import threading
import random
import traceback
import os


def create_test_results_dashboard(parent_window=None):
    """
    Dashboard to visualize the test results from Firestore database.
    """
    # If no parent window is provided, create a new root window
    if parent_window is None:
        root = tk.Tk()
        root.title("SMART Test Results Dashboard")
        root.geometry("1200x950")
    else:
        root = parent_window
        if isinstance(root, tk.Toplevel):
            root.title("SMART Test Results Dashboard")
            root.geometry("1200x950")

    # Create the dashboard
    dashboard = TestResultsDashboard(root)

    # If we created our own root, start the mainloop
    if parent_window is None:
        root.mainloop()

    return dashboard


class TestResultsDashboard:
    def __init__(self, root):
        self.root = root

        # Main frame to hold all dashboard elements
        self.main_frame = ttk.Frame(root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Create header
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        # Title
        title_label = ttk.Label(header_frame, text="SMART Test Results Dashboard",
                                font=("Arial", 24, "bold"))
        title_label.pack(side=tk.LEFT)

        # Refresh button
        refresh_btn = ttk.Button(header_frame, text="🔄 Refresh",
                                 command=self.refresh_data)
        refresh_btn.pack(side=tk.RIGHT, padx=10)

        # Time range filter
        filter_frame = ttk.Frame(header_frame)
        filter_frame.pack(side=tk.RIGHT, padx=20)

        ttk.Label(filter_frame, text="Time Range:").pack(side=tk.LEFT, padx=(0, 5))

        self.time_filter = ttk.Combobox(filter_frame, width=15, state="readonly",
                                        values=["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"])
        self.time_filter.current(3)  # Default to All time
        self.time_filter.pack(side=tk.LEFT)
        self.time_filter.bind("<<ComboboxSelected>>", lambda e: self.refresh_data())

        # KPI Cards Frame
        kpi_frame = ttk.Frame(self.main_frame)
        kpi_frame.pack(fill=tk.X, pady=10)

        # Create KPI cards with hard-coded values initially
        self.total_tests_label = self.create_kpi_card(kpi_frame, "Total Tests", "0", "#E0F7FA")
        self.success_rate_label = self.create_kpi_card(kpi_frame, "Success Rate", "0%", "#E8F5E9")
        self.failure_rate_label = self.create_kpi_card(kpi_frame, "Failure Rate", "0%", "#FFEBEE")
        self.avg_time_label = self.create_kpi_card(kpi_frame, "Avg Test Time", "0 sec", "#FFF8E1")

        # Charts area
        charts_frame = ttk.Frame(self.main_frame)
        charts_frame.pack(fill=tk.BOTH, expand=True)

        # Top row charts
        top_charts = ttk.Frame(charts_frame)
        top_charts.pack(fill=tk.X, expand=True, pady=5)

        # Chart 1: Test Types
        self.type_chart_frame = ttk.LabelFrame(top_charts, text="Tests by Type")
        self.type_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        # Chart 2: Test Status
        self.status_chart_frame = ttk.LabelFrame(top_charts, text="Test Status")
        self.status_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Bottom row charts
        bottom_charts = ttk.Frame(charts_frame)
        bottom_charts.pack(fill=tk.X, expand=True, pady=5)

        # Chart 3: Tests Over Time
        self.time_chart_frame = ttk.LabelFrame(bottom_charts, text="Tests Over Time")
        self.time_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        # Chart 4: Performance Metrics
        self.metrics_chart_frame = ttk.LabelFrame(bottom_charts, text="Performance Metrics")
        self.metrics_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Status bar
        self.status_var = tk.StringVar(value="Initializing dashboard...")
        status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(10, 0))

        # Display "Loading..." in charts initially
        self.show_loading_placeholders()

        # Load Firestore data immediately
        self.root.after(100, self.load_firebase_data)

    def show_loading_placeholders(self):
        """Display loading placeholders in the chart frames"""
        for frame in [self.type_chart_frame, self.status_chart_frame,
                      self.time_chart_frame, self.metrics_chart_frame]:
            # Clear the frame first
            for widget in frame.winfo_children():
                widget.destroy()
            # Add loading label
            loading_label = ttk.Label(frame, text="Loading data...", font=("Arial", 14))
            loading_label.pack(expand=True, pady=40)

    def create_kpi_card(self, parent, title, value, bg_color):
        """Create a KPI card with direct label"""
        # Card frame
        card = tk.Frame(parent, bd=1, relief=tk.RAISED)
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        # Inner colored frame
        inner = tk.Frame(card, bg=bg_color, padx=10, pady=10)
        inner.pack(fill=tk.BOTH, expand=True)

        # Title
        tk.Label(inner, text=title, font=("Arial", 14),
                 bg=bg_color, fg="#333333").pack(pady=(5, 10))

        # Value - return this label so we can update it later
        value_label = tk.Label(inner, text=value, font=("Arial", 24, "bold"),
                               bg=bg_color, fg="#000000")
        value_label.pack(pady=(0, 5))

        return value_label

    def update_kpi_values(self, total, success_rate, failure_rate, avg_time):
        """Update the KPI card values directly"""
        self.total_tests_label.config(text=str(total))
        self.success_rate_label.config(text=f"{success_rate:.1f}%")
        self.failure_rate_label.config(text=f"{failure_rate:.1f}%")

        if avg_time < 60:
            self.avg_time_label.config(text=f"{avg_time:.1f} sec")
        else:
            self.avg_time_label.config(text=f"{avg_time / 60:.1f} min")

    def create_pie_chart(self, frame, labels, values, title, colors=None):
        """Create a pie chart in the given frame"""
        # Clear the frame first
        for widget in frame.winfo_children():
            widget.destroy()

        figure, ax = plt.subplots(figsize=(5, 4), dpi=80)

        if colors:
            ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90, shadow=True, colors=colors)
        else:
            ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90, shadow=True)

        ax.axis('equal')
        ax.set_title(title)

        canvas = FigureCanvasTkAgg(figure, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def create_time_chart(self, frame, dates, counts):
        """Create a time chart with real data"""
        # Clear the frame first
        for widget in frame.winfo_children():
            widget.destroy()

        figure, ax = plt.subplots(figsize=(5, 4), dpi=80)
        ax.plot(dates, counts, marker='o', linestyle='-', color='blue')

        ax.set_xlabel('Date')
        ax.set_ylabel('Number of Tests')
        ax.set_title('Tests Run Per Day')

        plt.xticks(rotation=45)
        plt.tight_layout()

        canvas = FigureCanvasTkAgg(figure, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def create_metrics_chart(self, frame, metrics, values):
        """Create a metrics bar chart with real data"""
        # Clear the frame first
        for widget in frame.winfo_children():
            widget.destroy()

        figure, ax = plt.subplots(figsize=(5, 4), dpi=80)
        bars = ax.bar(metrics, values, color=['#1976D2', '#388E3C', '#FBC02D'])

        # Add value labels
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2., height + 1,
                    f'{height:.1f}%', ha='center', va='bottom')

        ax.set_ylim(0, 100)
        ax.set_ylabel('Percentage (%)')
        ax.set_title('Average System Resource Usage')

        plt.tight_layout()

        canvas = FigureCanvasTkAgg(figure, frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def refresh_data(self):
        """User-triggered refresh"""
        self.status_var.set("Refreshing data...")
        self.show_loading_placeholders()
        self.load_firebase_data()

    def load_firebase_data(self):
        """Try to load data from Firebase"""
        try:
            # Initialize Firebase if not already initialized
            try:
                app = firebase_admin.get_app()
                print(f"Using existing Firebase app: {app.name}")
            except ValueError:
                # Not initialized yet, use credentials
                try:
                    # Try to load from environment variable
                    cred_path = os.environ.get('FIREBASE_CREDENTIALS_PATH')
                    if cred_path and os.path.exists(cred_path):
                        cred = credentials.Certificate(cred_path)
                    else:
                        # Fall back to the original credentials
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
                    app = firebase_admin.initialize_app(cred)
                    print(f"Initialized new Firebase app: {app.name}")
                except Exception as init_error:
                    self.status_var.set(f"Firebase initialization error: {str(init_error)}")
                    traceback.print_exc()
                    # Show empty charts with "No data" message
                    self.show_empty_charts()
                    return

            # Get the time range
            time_filter = self.time_filter.get()
            self.status_var.set(f"Fetching data for {time_filter}...")

            # Start a thread to fetch data
            threading.Thread(target=self._fetch_firebase_data, args=(time_filter,), daemon=True).start()

        except Exception as e:
            self.status_var.set(f"Firebase connection error: {str(e)}")
            traceback.print_exc()
            # Show empty charts with "No data" message
            self.show_empty_charts()

    def show_empty_charts(self):
        """Display empty charts with 'No data' message"""
        # Update KPIs with zeros
        self.update_kpi_values(0, 0.0, 0.0, 0.0)

        # Clear and show "No data" in all chart frames
        for frame, title in [
            (self.type_chart_frame, "Tests by Type"),
            (self.status_chart_frame, "Test Status"),
            (self.time_chart_frame, "Tests Over Time"),
            (self.metrics_chart_frame, "Performance Metrics")
        ]:
            # Clear the frame
            for widget in frame.winfo_children():
                widget.destroy()

            # Add "No data" label
            no_data_label = ttk.Label(frame, text="No data available", font=("Arial", 14))
            no_data_label.pack(expand=True, pady=40)

        # Update status
        self.status_var.set("No data available for the selected time range")

    def _fetch_firebase_data(self, time_filter):
        """Fetch data from Firebase in a background thread"""
        try:
            # Get Firestore client
            db = firestore.client()
            results_ref = db.collection('test_results')

            # Calculate date range based on filter
            if time_filter == "Last 24 Hours":
                start_date = datetime.now() - timedelta(days=1)
            elif time_filter == "Last 7 Days":
                start_date = datetime.now() - timedelta(days=7)
            elif time_filter == "Last 30 Days":
                start_date = datetime.now() - timedelta(days=30)
            else:  # All Time
                start_date = datetime.now() - timedelta(days=365 * 10)  # Very far back

            # Retrieve all documents to work with directly
            print(f"Retrieving test results for {time_filter}...")
            all_docs = list(results_ref.stream())

            if not all_docs:
                self.root.after(0, lambda: self.status_var.set("No data found in Firestore"))
                self.root.after(0, self.show_empty_charts)
                return

            # Convert all documents to dictionaries with ID
            all_results = []
            for doc in all_docs:
                data = doc.to_dict()
                data['id'] = doc.id
                all_results.append(data)

            # Create a dataframe with all results
            df_all = pd.DataFrame(all_results)

            # Filter based on timestamp in Python rather than in Firestore query
            if 'timestamp' in df_all.columns:
                # Convert timestamps to datetime objects for comparison
                # Handle both string timestamps and firestore timestamps
                def convert_timestamp(ts):
                    if isinstance(ts, str):
                        try:
                            return pd.to_datetime(ts)
                        except:
                            return None
                    elif hasattr(ts, 'timestamp'):  # Firestore timestamp object
                        try:
                            return datetime.fromtimestamp(ts.timestamp())
                        except:
                            return None
                    return None

                # Convert timestamps
                df_all['timestamp_dt'] = df_all['timestamp'].apply(convert_timestamp)

                # Drop rows with invalid timestamps
                df_all = df_all.dropna(subset=['timestamp_dt'])

                # Filter based on the calculated start date
                mask = df_all['timestamp_dt'] >= start_date
                df_filtered = df_all[mask].copy()  # Create a copy to avoid SettingWithCopyWarning

                # Add date column from timestamp
                df_filtered['date'] = df_filtered['timestamp_dt'].dt.date

                # If we have results after filtering, use them
                if not df_filtered.empty:
                    # Update UI from main thread
                    self.root.after(0, lambda: self._update_ui_with_data(df_filtered))
                    self.root.after(0, lambda: self.status_var.set(
                        f"Showing data for {time_filter}. Found {len(df_filtered)} records."
                    ))
                    return
                else:
                    self.root.after(0, lambda: self.status_var.set(f"No data found for {time_filter}"))
                    self.root.after(0, self.show_empty_charts)
                    return

            # If we reach here, there's an issue with timestamps
            self.root.after(0, lambda: self.status_var.set("Could not filter by date: timestamp format issue"))

            # Fall back to showing all data
            if not df_all.empty:
                self.root.after(0, lambda: self._update_ui_with_data(df_all))
                self.root.after(0, lambda: self.status_var.set("Showing all data (date filtering unavailable)"))
            else:
                self.root.after(0, self.show_empty_charts)

        except Exception as e:
            self.root.after(0, lambda: self.status_var.set(f"Error fetching data: {str(e)}"))
            print(f"Error fetching Firebase data: {str(e)}")
            traceback.print_exc()
            self.root.after(0, self.show_empty_charts)

    def _update_ui_with_data(self, df):
        """Update UI with the fetched data"""
        try:
            # Calculate KPI values
            total_tests = len(df)

            success_count = len(df[df['status'] == 'Passed'])
            success_rate = success_count / total_tests * 100 if total_tests > 0 else 0

            failure_count = len(df[df['status'] == 'Failed'])
            failure_rate = failure_count / total_tests * 100 if total_tests > 0 else 0

            # Calculate average test time
            test_times = []
            for _, row in df.iterrows():
                if 'details' in row and isinstance(row['details'], dict):
                    if 'start_time' in row['details'] and 'end_time' in row['details']:
                        try:
                            start = datetime.strptime(row['details']['start_time'], "%Y-%m-%d %H:%M:%S")
                            end = datetime.strptime(row['details']['end_time'], "%Y-%m-%d %H:%M:%S")
                            duration = (end - start).total_seconds()
                            test_times.append(duration)
                        except Exception:
                            pass

            avg_time = sum(test_times) / len(test_times) if test_times else 0

            # Update KPIs
            self.update_kpi_values(total_tests, success_rate, failure_rate, avg_time)

            # Update charts with real data
            try:
                # 1. Test Types Chart
                if 'test_type' in df.columns:
                    type_counts = df['test_type'].value_counts()
                    self.create_pie_chart(
                        self.type_chart_frame,
                        type_counts.index,
                        type_counts.values,
                        "Test Distribution by Type"
                    )
                else:
                    for widget in self.type_chart_frame.winfo_children():
                        widget.destroy()
                    ttk.Label(self.type_chart_frame, text="No test type data available").pack(pady=40)

                # 2. Status Chart
                if 'status' in df.columns:
                    status_counts = df['status'].value_counts()
                    colors = {'Passed': 'green', 'Failed': 'red', 'Warning': 'orange', 'Running': 'blue'}
                    status_colors = [colors.get(status, 'gray') for status in status_counts.index]

                    self.create_pie_chart(
                        self.status_chart_frame,
                        status_counts.index,
                        status_counts.values,
                        "Test Results Distribution",
                        colors=status_colors
                    )
                else:
                    for widget in self.status_chart_frame.winfo_children():
                        widget.destroy()
                    ttk.Label(self.status_chart_frame, text="No status data available").pack(pady=40)

                # 3. Time Chart
                if 'date' in df.columns:
                    daily_counts = df.groupby('date').size()
                    self.create_time_chart(
                        self.time_chart_frame,
                        daily_counts.index,
                        daily_counts.values
                    )
                else:
                    for widget in self.time_chart_frame.winfo_children():
                        widget.destroy()
                    ttk.Label(self.time_chart_frame, text="No date data available").pack(pady=40)

                # 4. Metrics Chart
                cpu_usage = []
                memory_usage = []
                disk_usage = []

                for _, row in df.iterrows():
                    if 'details' in row and isinstance(row['details'], dict):
                        details = row['details']

                        # Handle None values or missing keys for CPU usage
                        if 'cpu_usage' in details and details['cpu_usage'] is not None:
                            try:
                                cpu_usage.append(float(details['cpu_usage']))
                            except (ValueError, TypeError):
                                pass

                        # Handle None values or missing keys for memory usage
                        if 'memory_usage' in details and details['memory_usage'] is not None:
                            try:
                                memory_usage.append(float(details['memory_usage']))
                            except (ValueError, TypeError):
                                pass

                        # Handle None values or missing keys for disk usage
                        if 'disk_usage' in details and details['disk_usage'] is not None:
                            try:
                                disk_usage.append(float(details['disk_usage']))
                            except (ValueError, TypeError):
                                pass

                if cpu_usage or memory_usage or disk_usage:
                    avg_cpu = sum(cpu_usage) / len(cpu_usage) if cpu_usage else 0
                    avg_memory = sum(memory_usage) / len(memory_usage) if memory_usage else 0
                    avg_disk = sum(disk_usage) / len(disk_usage) if disk_usage else 0

                    self.create_metrics_chart(
                        self.metrics_chart_frame,
                        ['CPU Usage', 'Memory Usage', 'Disk Usage'],
                        [avg_cpu, avg_memory, avg_disk]
                    )
                else:
                    for widget in self.metrics_chart_frame.winfo_children():
                        widget.destroy()
                    ttk.Label(self.metrics_chart_frame, text="No performance metrics available").pack(pady=40)

                # Update status
                self.status_var.set(
                    f"Data updated successfully. {total_tests} records found. Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )

            except Exception as chart_error:
                print(f"Error creating charts: {str(chart_error)}")
                traceback.print_exc()
                self.status_var.set(f"Error creating visualizations: {str(chart_error)}")

        except Exception as e:
            self.status_var.set(f"Error updating UI: {str(e)}")
            print(f"Error updating UI: {str(e)}")
            traceback.print_exc()
            self.show_empty_charts()


# For testing as standalone
if __name__ == "__main__":
    create_test_results_dashboard()