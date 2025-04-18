import tkinter as tk
from dependency_manager import check_system_tools, check_python_libs, install_dependencies
from prompt_manager import load_prompts, save_prompt
from api_interaction import check_api_status, analyze_test_output, suggest_next_test
from test_executor import run_tests
from gui_manager import create_gui

# درخواست رمز عبور sudo
sudo_password = tk.simpledialog.askstring("Sudo Password", "Enter your sudo password:", show="*")
if not sudo_password:
    tk.messagebox.showerror("Error", "Sudo password required. Exiting.")
    exit()

# بررسی وابستگی‌ها
missing_tools = check_system_tools()
missing_libs = check_python_libs()
if missing_tools or missing_libs:
    success, msg = install_dependencies(sudo_password, missing_tools, missing_libs)
    if not success:
        tk.messagebox.showerror("Error", f"Failed to install dependencies: {msg}")
        exit()

# بارگذاری پرامپت‌ها
prompts = load_prompts()

# ایجاد رابط کاربری
root, test_entry, start_button, output_text = create_gui()

# متغیر برای توقف تست‌ها
stop_event = tk.threading.Event()

# تابع شروع تست‌ها
def start_tests():
    commands = test_entry.get("1.0", tk.END).strip().splitlines()
    if not commands:
        tk.messagebox.showwarning("Warning", "Please enter tests.")
        return
    run_tests(commands, output_text, None, stop_event, None, None, sudo_password)

start_button.config(command=start_tests)

root.mainloop()