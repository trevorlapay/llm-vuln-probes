#!/usr/bin/env python3
"""
Script to run all supply chain vulnerability probes using Garak.

This script uses garak's standard CLI to run the supply chain probes
loaded from the local src/ directory. Works with any garak installation
without modifying it.

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
# PROBE CONFIGURATION
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
    """Validate configuration."""
    if API_KEY == "your-api-key-here":
        print("ERROR: Please set your API_KEY in the configuration section.")
        return False
    
    if TARGET_MODEL_NAME == "gpt-4":
        print("WARNING: Using default model 'gpt-4'. Make sure this matches your setup.")
    
    return True

def run_scans():
    """Execute all supply chain vulnerability scans using garak CLI."""
    print("[*] Supply Chain Vulnerability Scanner")
    print("=" * 50)
    print(f"Model Type: {TARGET_MODEL_TYPE}")
    print(f"Model Name: {TARGET_MODEL_NAME}")
    print(f"Probes: {', '.join(SUPPLY_CHAIN_PROBES)}")
    print(f"Generations per prompt: {GENERATIONS_PER_PROMPT}")
    print()
    
    if not validate_config():
        sys.exit(1)
    
    # Add src directory to Python path so garak can find the probes
    src_dir = str(Path(__file__).parent / "src")
    os.environ["PYTHONPATH"] = f"{src_dir}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"
    sys.path.insert(0, src_dir)
    
    # Verify garak is installed
    try:
        import garak
        print("[+] garak is installed")
    except ImportError:
        print("ERROR: garak is not installed. Please install it with: pip install garak")
        sys.exit(1)
    
    # Verify probes exist in src
    probe_file = Path(__file__).parent / "src" / "garak" / "probes" / "supply_chain.py"
    if not probe_file.exists():
        print(f"ERROR: Probe file not found: {probe_file}")
        sys.exit(1)
    
    print("[+] Probes found in src/garak/probes/supply_chain.py")
    
    # Set up environment variables for API access
    if TARGET_MODEL_TYPE == "openai":
        os.environ["OPENAI_API_KEY"] = API_KEY
    if API_BASE_URL != "https://api.openai.com/v1":
        os.environ["OPENAI_API_BASE"] = API_BASE_URL
    
    # Build garak command
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
    
    print("\n[*] Executing scan...")
    print(f"Command: {' '.join(cmd)}\n")
    
    # Run the scan
    try:
        result = subprocess.run(cmd, cwd=Path.cwd())
        if result.returncode == 0:
            print("\n[+] Scan completed successfully!")
            print(f"Results saved to {REPORT_PREFIX}* files")
        else:
            print(f"\n[-] Scan failed with return code {result.returncode}")
            sys.exit(result.returncode)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error running scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_scans()
