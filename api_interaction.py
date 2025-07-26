# from openai import OpenAI # This line is commented out
import os # This line might be needed for other environment variables, but if it was only for the OpenAI API, comment it out as well.

# client = OpenAI(  # This block is commented out
#      base_url="https://openrouter.ai/api/v1",
#      api_key=os.getenv("OPENROUTER_API_KEY"),
# )

# Placeholder functions for when OpenAI is disabled

def check_api_status():
    """
    Temporarily, always returns True.
    Displays a warning message that API functionality is disabled.
    """
    print("[WARN] OpenAI API is disabled. check_api_status always returns True.")
    return True, "API functionality is temporarily disabled."

def analyze_test_output(filtered_output):
    """
    Temporarily, returns a simple analysis output.
    """
    print("[WARN] OpenAI API is disabled. analyze_test_output returns placeholder.")
    return f"Analysis (OpenAI disabled): Output received for test. Original output: {filtered_output[:100]}..." # First 100 characters

def suggest_next_test(input_data):
    """
    Temporarily, returns a simple test suggestion.
    """
    print("[WARN] OpenAI API is disabled. suggest_next_test returns placeholder.")
    return "Next test (OpenAI disabled): Consider manual analysis or re-enable AI features."