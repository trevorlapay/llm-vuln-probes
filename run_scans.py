#!/usr/bin/env python3
"""
Script to run all supply chain vulnerability probes using Garak.

This script automatically installs the supply chain probes into garak
and then runs them against a target model. Assuming garak is installed
locally, this script requires no additional setup.

Configure your model settings below before running.
"""

import os
import shutil
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
# PROBE CONFIGURATION - Don't modify unless you know what you're doing
# =============================================================================

SUPPLY_CHAIN_PROBES = [
    "supply_chain.VulnDepMinimal",
    "supply_chain.VulnDepSteered",
    "supply_chain.VulnDepVersionChoice",
    "supply_chain.VulnDepCodeReview"
]

# =============================================================================
# PROBE INSTALLATION
# =============================================================================

def ensure_probes_installed():
    """Install supply chain probes into the local garak installation."""
    try:
        import garak
        garak_path = Path(garak.__path__[0])
    except ImportError:
        print("ERROR: garak is not installed. Please install it with: pip install garak")
        sys.exit(1)
    
    repo_root = Path(__file__).parent
    src_path = repo_root / "src" / "garak"
    
    # Define source and destination paths
    probe_src = src_path / "probes" / "supply_chain.py"
    probe_dst = garak_path / "probes" / "supply_chain.py"
    
    detector_src = src_path / "detectors" / "supply_chain.py"
    detector_dst = garak_path / "detectors" / "supply_chain.py"
    
    data_src = src_path / "data" / "supply_chain" / "vuln_packages.json"
    data_dst = garak_path / "data" / "supply_chain" / "vuln_packages.json"
    
    # Check if already installed
    if probe_dst.exists() and detector_dst.exists() and data_dst.exists():
        return True
    
    print("[*] Installing supply chain probes into garak...")
    
    # Verify source files exist
    for src_file in [probe_src, detector_src, data_src]:
        if not src_file.exists():
            print(f"ERROR: Source file not found: {src_file}")
            sys.exit(1)
    
    # Copy files
    try:
        probe_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(probe_src, probe_dst)
        print(f"  [+] Installed probe to {probe_dst}")
        
        detector_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(detector_src, detector_dst)
        print(f"  [+] Installed detector to {detector_dst}")
        
        data_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(data_src, data_dst)
        print(f"  [+] Installed data to {data_dst}")
        
        print("[+] Probes installed successfully!")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to install probes: {e}")
        return False

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

def run_scans():
    """Execute all supply chain vulnerability scans."""
    print("[*] Supply Chain Vulnerability Scanner")
    print("=" * 50)
    
    # Ensure probes are installed
    print("\n[*] Checking probe installation...")
    if not ensure_probes_installed():
        print("ERROR: Failed to install probes")
        sys.exit(1)
    
    print(f"\nModel Type: {TARGET_MODEL_TYPE}")
    print(f"Model Name: {TARGET_MODEL_NAME}")
    print(f"Probes: {', '.join(SUPPLY_CHAIN_PROBES)}")
    print(f"Generations per prompt: {GENERATIONS_PER_PROMPT}")
    print()
    
    if not validate_config():
        sys.exit(1)
    
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
    
    print("Executing command:")
    print(" ".join(cmd))
    print()
    
    # Set environment variables for API access
    env = os.environ.copy()
    if TARGET_MODEL_TYPE == "openai":
        env["OPENAI_API_KEY"] = API_KEY
    if API_BASE_URL != "https://api.openai.com/v1":
        env["OPENAI_API_BASE"] = API_BASE_URL
    
    # Run the scan
    try:
        result = subprocess.run(cmd, cwd=Path.cwd(), env=env)
        if result.returncode == 0:
            print("\n[+] Scan completed successfully!")
            print(f"Check the {REPORT_PREFIX}* files for results.")
        else:
            print(f"\n[-] Scan failed with return code {result.returncode}")
            sys.exit(result.returncode)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error running scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_scans()
