#!/usr/bin/env python3
"""Debug script to test OpenAICompatible generator."""

import os
import sys
import io

# Set your environment variables here or via command line
# os.environ['OPENAICOMPATIBLE_API_KEY'] = 'your-key'
# os.environ['OPENAI_BASE_URL'] = 'http://your-endpoint:8000/v1'

# Or pass as command line args: python debug_generator.py <api_key> <base_url> [model_name]
if len(sys.argv) > 1:
    os.environ['OPENAICOMPATIBLE_API_KEY'] = sys.argv[1]
    print(f"Set API_KEY from argv[1]: {sys.argv[1][:10]}...")
if len(sys.argv) > 2:
    os.environ['OPENAI_BASE_URL'] = sys.argv[2]
    print(f"Set BASE_URL from argv[2]: {sys.argv[2]}")
if len(sys.argv) > 3:
    MODEL_NAME = sys.argv[3]
    print(f"Set MODEL_NAME from argv[3]: {MODEL_NAME}")
else:
    MODEL_NAME = "openai/gpt-oss-120b"

# Or pass as command line args: python debug_generator.py <api_key> <base_url> [model_name]
if len(sys.argv) > 1:
    os.environ['OPENAICOMPATIBLE_API_KEY'] = sys.argv[1]
if len(sys.argv) > 2:
    os.environ['OPENAI_BASE_URL'] = sys.argv[2]
if len(sys.argv) > 3:
    MODEL_NAME = sys.argv[3]
else:
    MODEL_NAME = "openai/gpt-oss-120b"

BASE_URL = os.environ.get('OPENAI_BASE_URL', '')
API_KEY = os.environ.get('OPENAICOMPATIBLE_API_KEY', '')

print(f"DEBUG: argv = {sys.argv}")
print(f"API Key: {'Set' if API_KEY else 'NOT SET'}")
print(f"Model: {MODEL_NAME}")
print(f"Base URL: '{BASE_URL}'")

if not BASE_URL:
    print("ERROR: No base URL set!")
    sys.exit(1)
if not API_KEY:
    print("ERROR: No API key set!")
    sys.exit(1)

# Now redirect stdout/stderr
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

sys.path.insert(0, 'src')
import garak._config as _config
_config.load_base_config()
_config.transient.reportfile = io.StringIO()
_config.run.generations = 1

from garak.generators.openai import OpenAICompatible
from garak.attempt import Conversation, Turn, Message

print(f"\nCreating generator...")
gen = OpenAICompatible(MODEL_NAME, config_root=_config)
gen.uri = BASE_URL

print(f"Generator URI: {gen.uri}")
print(f"Generator class: {gen.fullname}")

# Try a simple generation
conv = Conversation([
    Turn(role='user', content=Message(text='Say "hello" and nothing else.', lang='en'))
])

print("\nAttempting generation...")
try:
    result = gen.generate(conv)
    print(f"Result type: {type(result)}")
    print(f"Result: {result}")
    if result:
        for i, msg in enumerate(result):
            print(f"  Message {i}: {msg}")
            print(f"    text: {msg.text if hasattr(msg, 'text') else 'NO TEXT ATTR'}")
            print(f"    __dict__: {msg.__dict__ if hasattr(msg, '__dict__') else 'NO DICT'}")
    else:
        print("Result is empty!")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
