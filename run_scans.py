#!/usr/bin/env python3
"""Run Garak vulnerability scans on specified models.

Usage:
    python run_scans.py [--target_type TYPE] [--target_name NAME] [--probes PROBES] [--detectors DETECTORS]
    
Or set environment variables:
    GARAK_TARGET_TYPE=huggingface GARAK_TARGET_NAME=gpt2 python run_scans.py

Examples:
    python run_scans.py --target_type test --target_name Lipsum
    python run_scans.py --target_type huggingface --target_name gpt2 --probes encoding
    python run_scans.py --target_type openai --target_name gpt-4o-mini --probes supply_chain
"""

import argparse
import json
import logging
import os
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
    
    _config.plugins.target_type = args.target_type
    _config.plugins.target_name = args.target_name
    
    _config.transient.reportfile = open(args.output, "w", encoding="utf-8")
    
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def load_generator(target_type: str, target_name: str):
    """Load a generator for the specified model type and name."""
    import io
    import sys
    
    plugin_path = f"generators.{target_type}.{target_name}"
    
    old_stdout = sys.stdout
    sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8', errors='replace')
    
    try:
        generator = _plugins.load_plugin(plugin_path, config_root=_config)
        if generator:
            sys.stdout = old_stdout
            return generator
    except Exception as e:
        sys.stdout = old_stdout
        raise ValueError(f"Could not load generator {plugin_path}: {e}")
    
    sys.stdout = old_stdout


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


def run_probe(generator, probe_name: str, detector_names: list, verbose: int = 0):
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
    
    for attempt in attempts:
        for detector_name, detector in detectors:
            try:
                attempt.detector_results[detector_name] = detector.detect(attempt)
            except Exception as e:
                logging.warning(f"Detector failed: {e}")
    
    return attempts


def main():
    parser = argparse.ArgumentParser(description="Run Garak vulnerability scans")
    parser.add_argument("--target_type", "-t", default=os.environ.get("GARAK_TARGET_TYPE", "test"),
                        help="Model type (env: GARAK_TARGET_TYPE)")
    parser.add_argument("--target_name", "-n", default=os.environ.get("GARAK_TARGET_NAME", "Lipsum"),
                        help="Model name (env: GARAK_TARGET_NAME)")
    parser.add_argument("--probes", "-p", default="encoding.InjectBase64",
                        help="Comma-separated probes (default: encoding.InjectBase64)")
    parser.add_argument("--detectors", "-d", default="encoding.DecodeMatch",
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
    
    print(f"Initializing Garak ({args.target_type}/{args.target_name})...")
    setup_config(args)
    
    try:
        generator = load_generator(args.target_type, args.target_name)
        print(f"Loaded generator: {generator.fullname}")
    except Exception as e:
        print(f"ERROR: Failed to load generator: {e}")
        return 1
    
    probe_names = get_probe_names(args.probes)
    detector_names = get_detector_names(args.detectors)
    
    print(f"Running {len(probe_names)} probe(s): {probe_names}")
    
    all_attempts = []
    for probe_name in probe_names:
        attempts = run_probe(generator, probe_name, detector_names, args.verbose)
        all_attempts.extend(attempts)
    
    print(f"\n{'='*60}")
    print(f"Complete. {len(all_attempts)} attempts. Output: {args.output}")
    
    _config.transient.reportfile.close()
    
    with open(args.output.replace(".jsonl", "_summary.json"), "w") as f:
        json.dump({"probes": probe_names, "attempts": len(all_attempts)}, f)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
