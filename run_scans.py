#!/usr/bin/env python3
"""Run Garak vulnerability scans on specified models.

Usage:
    python run_scans.py [--target_type TYPE] [--target_name NAME] [--probes PROBES] [--detectors DETECTORS]
    
Examples:
    python run_scans.py --target_type test --target_name Lipsum
    python run_scans.py --target_type huggingface --target_name gpt2 --probes encoding
    python run_scans.py --target_type openai --target_name gpt-4o-mini --probes supply_chain
"""

import os  # Must be at top for MODEL_CONFIG

# =============================================================================
# CONFIGURATION - Edit these values or set environment variables
# =============================================================================
# 
# Model Configuration (can also set via environment variables):
#   GARAK_TARGET_TYPE=openai GARAK_TARGET_NAME=OpenAIGenerator python run_scans.py
#
MODEL_CONFIG = {
    # Target type: test, huggingface, openai, ollama, litellm, etc.
    "target_type": os.environ.get("GARAK_TARGET_TYPE", "test"),
    
    # Generator class: Lipsum, OpenAIGenerator, OpenAICompatible, HuggingFace, OllamaGenerator, etc.
    # See --list output for all available generators
    "target_name": os.environ.get("GARAK_TARGET_NAME", "Lipsum"),
    
    # Actual model name to use (for OpenAI, Ollama, LiteLLM, etc.)
    # This overrides target_name for specifying the model
    "model_name": os.environ.get("GARAK_MODEL_NAME", ""),
    
    # API Key - set via environment variable or put your key here
    #   e.g. "sk-your-api-key-here" or set OPENAI_API_KEY env var
    "api_key": os.environ.get("OPENAI_API_KEY", os.environ.get("GARAK_API_KEY", "")),
    
    # Base URL - for custom API endpoints (e.g., Ollama, LiteLLM, custom OpenAI endpoint)
    #   e.g. "http://localhost:11434" for Ollama
    "base_url": os.environ.get("GARAK_BASE_URL", os.environ.get("OPENAI_BASE_URL", "")),
}
# =============================================================================

import argparse
import json
import logging
import sys
from pathlib import Path

# Add local src to path for custom probes/detectors
_local_src = Path(__file__).parent / "src"
if _local_src.exists():
    sys.path.insert(0, str(_local_src))

# Fix Windows console encoding issues BEFORE importing garak
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import garak._config as _config
from garak import _plugins

# Lazy-load local probes/detectors
_local_probes_path = _local_src / "garak" / "probes" / "supply_chain.py"
_local_detectors_path = _local_src / "garak" / "detectors" / "supply_chain.py"


def setup_config(args):
    """Initialize garak configuration."""
    _config.load_base_config()
    
    _config.run.seed = args.seed
    _config.run.generations = args.generations
    
    if args.verbose:
        _config.system.verbose = args.verbose
    
    # Use command line args, or fall back to MODEL_CONFIG, or environment variables
    target_type = args.target_type or MODEL_CONFIG["target_type"]
    generator_class = args.target_name or MODEL_CONFIG["target_name"]
    
    # The actual model name to use (e.g., "gpt-4o-mini", "gpt2", etc.)
    # Falls back to generator_class if not specified separately
    model_name = args.model or MODEL_CONFIG.get("model_name") or generator_class
    
    _config.plugins.target_type = target_type
    _config.plugins.target_name = model_name  # This is the actual model name
    
    # Set API key if provided in config (for OpenAI, LiteLLM, etc.)
    if MODEL_CONFIG["api_key"]:
        os.environ.setdefault("OPENAI_API_KEY", MODEL_CONFIG["api_key"])
    
    # Set base URL if provided (for Ollama, LiteLLM, custom endpoints)
    if MODEL_CONFIG["base_url"]:
        os.environ.setdefault("OPENAI_BASE_URL", MODEL_CONFIG["base_url"])
    
    # Create a dummy file that swallows writes (we handle our own output)
    import io
    _config.transient.reportfile = io.StringIO()
    
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    
    return target_type, generator_class, model_name


def load_generator(target_type: str, generator_class: str, model_name: str = None):
    """Load a generator for the specified model type and name."""
    import io
    import sys
    import importlib
    
    # Use model_name if provided, otherwise fall back to generator_class
    actual_model = model_name or generator_class
    plugin_path = f"generators.{target_type}.{generator_class}"
    
    old_stdout = sys.stdout
    sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8', errors='replace')
    
    try:
        # Import the generator module and get class
        mod = importlib.import_module(f"garak.generators.{target_type}")
        klass = getattr(mod, generator_class)
        
        # Check if base_url is provided in MODEL_CONFIG
        base_url = MODEL_CONFIG.get("base_url", "")
        
        # Ensure base_url has /v1/ suffix for OpenAI-compatible APIs
        if base_url and not base_url.endswith("/v1"):
            base_url = base_url.rstrip("/") + "/v1"
        
        # For OpenAI-compatible generators, inject base_url if provided
        original_defaults = None
        if base_url and hasattr(klass, 'DEFAULT_PARAMS'):
            original_defaults = klass.DEFAULT_PARAMS.copy()
            klass.DEFAULT_PARAMS = klass.DEFAULT_PARAMS | {"uri": base_url}
        
        # For OpenAI and similar generators, pass model name as first arg
        if model_name and model_name != generator_class:
            generator = klass(model_name, config_root=_config)
        else:
            generator = klass(config_root=_config)
        
        # Restore DEFAULT_PARAMS after instantiation
        if original_defaults is not None:
            klass.DEFAULT_PARAMS = original_defaults
        
        sys.stdout = old_stdout
        return generator
        
    except Exception as e:
        sys.stdout = old_stdout
        raise ValueError(f"Could not load generator {plugin_path}: {e}")


def list_plugins():
    """List all available plugins."""
    print("\n=== Available Probes ===")
    for name, active in _plugins.enumerate_plugins("probes"):
        print(f"  {name} [{'active' if active else 'inactive'}]")
    
    print("\n=== Available Detectors ===")
    for name, active in _plugins.enumerate_plugins("detectors"):
        print(f"  {name} [{'active' if active else 'inactive'}]")
    
    print("\n=== Available Generators ===")
    for name, active in _plugins.enumerate_plugins("generators"):
        print(f"  {name} [{'active' if active else 'inactive'}]")


def get_probe_names(probe_spec: str):
    """Get list of probe class names from a probe spec."""
    if not probe_spec or probe_spec.lower() in ("all", "*", "auto"):
        return [name for name, active in _plugins.enumerate_plugins("probes") if active]
    
    # Special case: "supply_chain" runs all supply_chain probes
    if probe_spec.strip() == "supply_chain":
        return [
            "probes.supply_chain.VulnDepMinimal",
            "probes.supply_chain.VulnDepSteered",
            "probes.supply_chain.VulnDepVersionChoice",
            "probes.supply_chain.VulnDepCodeReview",
        ]
    
    probe_names = []
    for part in probe_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if part.startswith("probes."):
            probe_names.append(part)
        else:
            probe_names.append(f"probes.{part}")
    return probe_names


def get_detector_names(detector_spec: str):
    """Get list of detector class names."""
    if not detector_spec or detector_spec.lower() == "auto":
        return ["detectors.always.Fail"]
    
    detector_names = []
    for part in detector_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if part.startswith("detectors."):
            detector_names.append(part)
        else:
            detector_names.append(f"detectors.{part}")
    return detector_names


def run_probe(generator, probe_name: str, detector_names: list, verbose: int = 0, output_file: str = "garak_results.jsonl"):
    """Run a single probe against the generator with specified detectors."""
    print(f"\n{'='*60}")
    print(f"Running probe: {probe_name}")
    print(f"Using detectors: {', '.join(detector_names)}")
    print(f"{'='*60}")
    
    import io
    import sys
    
    # Try direct import for local probes first (bypasses plugin system)
    probe = None
    if "supply_chain" in probe_name and _local_probes_path.exists():
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("supply_chain_probes", _local_probes_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                old_stdout = sys.stdout
                sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8', errors='replace')
                spec.loader.exec_module(module)
                sys.stdout = old_stdout
                class_name = probe_name.split(".")[-1]
                probe = getattr(module, class_name)(config_root=_config)
        except Exception as e:
            sys.stdout = old_stdout
            print(f"ERROR: Failed to load probe {probe_name}: {e}")
            return []
    else:
        # Use plugin system for standard probes
        old_stdout = sys.stdout
        sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8', errors='replace')
        try:
            probe = _plugins.load_plugin(probe_name, config_root=_config)
        except Exception as e:
            pass
        sys.stdout = old_stdout
    
    if probe is None or not hasattr(probe, 'prompts') or not probe.prompts:
        print(f"WARNING: Probe {probe_name} has no prompts or failed to load, skipping")
        return []
    
    print(f"Probe has {len(probe.prompts)} prompts")
    
    detectors = []
    for detector_name in detector_names:
        detector = None
        
        # Try direct import for local detectors first
        if "supply_chain" in detector_name and _local_detectors_path.exists():
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location("supply_chain_detectors", _local_detectors_path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    old_stdout = sys.stdout
                    sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8', errors='replace')
                    spec.loader.exec_module(module)
                    sys.stdout = old_stdout
                    class_name = detector_name.split(".")[-1]
                    detector = getattr(module, class_name)(config_root=_config)
            except Exception as e:
                sys.stdout = old_stdout
                print(f"WARNING: Failed to load detector {detector_name}: {e}")
        else:
            # Use plugin system for standard detectors
            old_stdout = sys.stdout
            sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8', errors='replace')
            try:
                detector = _plugins.load_plugin(detector_name, config_root=_config)
            except Exception:
                pass
            sys.stdout = old_stdout
        
        if detector:
            detectors.append((detector_name, detector))
    
    if not detectors:
        print(f"ERROR: No detectors loaded, skipping")
        return []
    
    try:
        attempts = probe.probe(generator)
    except Exception as e:
        print(f"ERROR: Probe failed: {e}")
        if verbose > 1:
            import traceback
            traceback.print_exc()
        return []
    
    print(f"Completed {len(attempts)} attempts")
    
    # Run detectors and save results
    import json
    
    for attempt in attempts:
        for detector_name, detector in detectors:
            try:
                attempt.detector_results[detector_name] = detector.detect(attempt)
            except Exception as e:
                print(f"WARNING: Detector {detector_name} failed: {e}")
    
    # Write results to file
    import json

    file_mode = "w" if not Path(output_file).exists() else "a"
    with open(output_file, file_mode, encoding="utf-8") as f:
        for attempt in attempts:
            # Use garak's built-in as_dict() method for proper serialization
            # of Message, Conversation, Turn and other garak objects
            attempt_record = attempt.as_dict()
            # Add detector results to the record
            attempt_record["detector_results"] = {
                name: list(results) if results else []
                for name, results in attempt.detector_results.items()
            }
            f.write(json.dumps(attempt_record, ensure_ascii=False) + "\n")
    
    return attempts


def main():
    parser = argparse.ArgumentParser(description="Run Garak vulnerability scans")
    parser.add_argument("--target_type", "-t", default=None,
                        help="Model type (env: GARAK_TARGET_TYPE, or edit MODEL_CONFIG in file)")
    parser.add_argument("--target_name", "-n", default=None,
                        help="Generator class (env: GARAK_TARGET_NAME, e.g. OpenAIGenerator)")
    parser.add_argument("--model", "-m", default=None,
                        help="Actual model name (env: GARAK_MODEL_NAME, e.g. gpt-4o-mini)")
    parser.add_argument("--probes", "-p", default="supply_chain",
                        help="Comma-separated probes (default: supply_chain - runs all supply_chain probes)")
    parser.add_argument("--detectors", "-d", default="supply_chain.VulnDepDetector",
                        help="Comma-separated detectors (default: encoding.DecodeMatch)")
    parser.add_argument("--generations", "-g", type=int, default=1, help="Generations per prompt")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--output", "-o", default="garak_results.jsonl", help="Output file")
    parser.add_argument("--verbose", "-v", action="count", default=0)
    parser.add_argument("--list", action="store_true", help="List plugins")
    
    args = parser.parse_args()
    
    if args.list:
        _config.load_base_config()
        list_plugins()
        return 0
    
    target_type, generator_class, model_name = setup_config(args)
    
    print(f"Initializing Garak ({target_type}/{model_name})...")
    print(f"API Key: {'Set' if MODEL_CONFIG['api_key'] else 'Not set'}")
    print(f"Base URL: {MODEL_CONFIG['base_url'] or 'Not set'}")
    
    try:
        generator = load_generator(target_type, generator_class, model_name)
        print(f"Loaded generator: {generator.fullname}")
    except Exception as e:
        print(f"ERROR: Failed to load generator: {e}")
        return 1
    
    probe_names = get_probe_names(args.probes)
    detector_names = get_detector_names(args.detectors)
    
    print(f"Running {len(probe_names)} probe(s): {probe_names}")
    
    all_attempts = []
    for probe_name in probe_names:
        attempts = run_probe(generator, probe_name, detector_names, args.verbose, args.output)
        all_attempts.extend(attempts)
    
    print(f"\n{'='*60}")
    print(f"Complete. {len(all_attempts)} attempts. Output: {args.output}")
    
    with open(args.output.replace(".jsonl", "_summary.json"), "w") as f:
        json.dump({"probes": probe_names, "attempts": len(all_attempts)}, f)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
