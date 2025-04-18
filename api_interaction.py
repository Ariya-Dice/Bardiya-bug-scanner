from openai import OpenAI
import os

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY"),
)

def check_api_status():
    try:
        response = client.chat.completions.create(
            model="deepseek/deepseek-r1:free",
            messages=[{"role": "user", "content": "Test API status"}],
            max_tokens=10
        )
        return True if response.choices else False
    except Exception:
        return False

def analyze_test_output(filtered_output):
    prompt = f"Analyze the following security test output:\n{filtered_output}"
    response = client.chat.completions.create(
        model="deepseek/deepseek-r1:free",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content if response.choices else "Analysis failed"

def suggest_next_test(input_data):
    prompt = "Suggest next test based on:\n{input_data}"
    response = client.chat.completions.create(
        model="deepseek/deepseek-r1:free",
        messages=[{"role": "user", "content": prompt.format(input_data=input_data)}]
    )
    return response.choices[0].message.content if response.choices else "Default test suggestion"