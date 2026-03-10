#!/usr/bin/env python3
"""
Script to run all supply chain vulnerability probes using Garak.

This script runs the four supply chain probe variants against a target model:
- VulnDepMinimal (P1): Task-only prompts with no library hints
- VulnDepSteered (P2): Library named, model picks version
- VulnDepVersionChoice (P3): Explicit version selection requested
- VulnDepCodeReview (P4): Model reviews code with vulnerable versions

Configure your model settings below before running.
"""

import os
import subprocess
import sys
from pathlib import Path

# =============================================================================
# CONFIGURATION - Edit these values for your setup
# =============================================================================

# Model configuration
TARGET_MODEL_TYPE = "openai"  # e.g., "openai", "huggingface", "replicate", etc.
TARGET_MODEL_NAME = "gpt-4"   # e.g., "gpt-4", "gpt-3.5-turbo", model path, etc.

# API configuration (for OpenAI-style models)
API_KEY = "your-api-key-here"  # Replace with your actual API key
API_BASE_URL = "https://api.openai.com/v1"  # Optional: custom API base URL

# Scan configuration
GENERATIONS_PER_PROMPT = 1  # Number of generations per prompt
SEED = 42  # Random seed for reproducibility
VERBOSE = True  # Enable verbose output

# Report configuration
REPORT_PREFIX = "supply_chain_scan"  # Prefix for output files

# =============================================================================
# PROBE CONFIGURATION - Don\'t modify unless you know what you\'re doing
# =============================================================================

SUPPLY_CHAIN_PROBES = [
    "supply_chain.VulnDepMinimal",
    "supply_chain.VulnDepSteered", 
    "supply_chain.VulnDepVersionChoice",
    "supply_chain.VulnDepCodeReview"
]

# =============================================================================
# MAIN EXECUTION
# =============================================================================

def validate_config():
    """Validate that required configuration is set."""
    if API_KEY == "your-api-key-here":
        print("ERROR: Please set your API_KEY in the configuration section.")
        return False
    
    if TARGET_MODEL_NAME == "gpt-4":
        print("WARNING: Using default model 'gpt-4'. Make sure this matches your setup.")
    
    return True

def build_garak_command():
    """Build the garak command with all configured options."""
    cmd = [
        sys.executable, "-m", "garak",
        "--model_type", TARGET_MODEL_TYPE,
        "--model_name", TARGET_MODEL_NAME,
        "--generations", str(GENERATIONS_PER_PROMPT),
        "--seed", str(SEED),
        "--report_prefix", REPORT_PREFIX,
    ]
    
    # Add probes
    probe_list = ",".join(SUPPLY_CHAIN_PROBES)
    cmd.extend(["--probes", probe_list])
    
    # Add verbosity
    if VERBOSE:
        cmd.append("-v")
    
    return cmd

def run_scans():
    """Execute all supply chain vulnerability scans."""
    print("🔍 Supply Chain Vulnerability Scanner")
    print("=" * 50)
    print(f"Model Type: {TARGET_MODEL_TYPE}")
    print(f"Model Name: {TARGET_MODEL_NAME}")
    print(f"Probes: {', '.join(SUPPLY_CHAIN_PROBES)}")
    print(f"Generations per prompt: {GENERATIONS_PER_PROMPT}")
    print()
    
    if not validate_config():
        sys.exit(1)
    
    # Build and execute command
    cmd = build_garak_command()
    print("Executing command:")
    print(" ".join(cmd))
    print()
    
    # Set environment variables for API access
    env = os.environ.copy()
    if API_KEY:
        if TARGET_MODEL_TYPE == "openai":
            env["OPENAI_API_KEY"] = API_KEY
        # Add other model types as needed
    if API_BASE_URL != "https://api.openai.com/v1":
        if TARGET_MODEL_TYPE == "openai":
            env["OPENAI_API_BASE"] = API_BASE_URL
    
    try:
        result = subprocess.run(cmd, cwd=Path.cwd(), env=env)
        if result.returncode == 0:
            print("\n✅ Scan completed successfully!")
            print(f"Check the {REPORT_PREFIX}* files for results.")
        else:
            print(f"\n❌ Scan failed with return code {result.returncode}")
            sys.exit(result.returncode)
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Error running scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_scans()
