#!/usr/bin/env python3
"""Debug script to test OpenAICompatible generator."""

import os
import sys

# Pass as command line args: python debug_generator.py <api_key> <base_url> [model_name]
API_KEY = sys.argv[1] if len(sys.argv) > 1 else ""
BASE_URL = sys.argv[2] if len(sys.argv) > 2 else ""
MODEL_NAME = sys.argv[3] if len(sys.argv) > 3 else "openai/gpt-oss-120b"

print(f"Settings:")
print(f"  API_KEY: {'Set' if API_KEY else 'NOT SET'}")
print(f"  BASE_URL: {BASE_URL}")
print(f"  MODEL_NAME: {MODEL_NAME}")
print()

# Set env vars BEFORE importing garak
if API_KEY:
    os.environ['OPENAICOMPATIBLE_API_KEY'] = API_KEY
    
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

sys.path.insert(0, 'src')

# Import garak generators BEFORE we modify DEFAULT_PARAMS
from garak.generators.openai import OpenAICompatible

# Now modify DEFAULT_PARAMS before creating the generator
# Ensure base_url ends with /v1
if BASE_URL:
    if not BASE_URL.endswith("/v1"):
        BASE_URL = BASE_URL.rstrip("/") + "/v1"
    print(f"Setting DEFAULT_PARAMS['uri'] to: {BASE_URL}")
    OpenAICompatible.DEFAULT_PARAMS = OpenAICompatible.DEFAULT_PARAMS | {"uri": BASE_URL}

print(f"DEFAULT_PARAMS['uri'] = {OpenAICompatible.DEFAULT_PARAMS.get('uri')}")
print()

import garak._config as _config
_config.load_base_config()
_config.transient.reportfile = io.StringIO()

print("Creating generator...")
gen = OpenAICompatible(MODEL_NAME, config_root=_config)
print(f"Generator URI: {gen.uri}")
print(f"Generator class: {gen.fullname}")

from garak.attempt import Conversation, Turn, Message

# Try a simple generation
conv = Conversation([
    Turn(role='user', content=Message(text='Say "hello" and nothing else.', lang='en'))
])

print("\nAttempting generation...")
try:
    result = gen.generate(conv)
    print(f"Result type: {type(result)}")
    if result:
        for i, msg in enumerate(result):
            print(f"  Message {i}: text='{msg.text if hasattr(msg, 'text') else 'NO TEXT'}'")
    else:
        print("Result is empty!")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
