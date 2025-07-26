import json
import os

PROMPT_FILE = "prompts.json"

def load_prompts():
    if os.path.exists(PROMPT_FILE):
        with open(PROMPT_FILE, "r") as f:
            return json.load(f)
    return {"Default": "default_prompt"}

def save_prompt(name, prompt):
    prompts = load_prompts()
    prompts[name] = prompt
    with open(PROMPT_FILE, "w") as f:
        json.dump(prompts, f, indent=4)