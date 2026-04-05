#!/usr/bin/env python3
"""
Driver Batch Processing Script

This script analyzes a batch of Windows drivers to identify security-relevant
sinks and ranks them by vulnerability potential.

Usage:
    python process_batch.py --dataset-dir dataset/ --output-dir sorted_drivers/

The script:
1. Loads each driver using idalib (same logic as ida_mcp)
2. Parses the Import Address Table (IAT)
3. Scans .text section for security sinks
4. Ranks drivers by sink count and priority
5. Renames drivers with priority scores (1_highest.sys, 2_second.sys, etc.)
"""

import argparse
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Change to script directory
script_dir = Path(__file__).parent.resolve()
os.chdir(script_dir)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Sink definitions with priority points
SINKS = {
    'WriteMsr': 20,           # MSR write operations
    'MmMapIoSpace': 50,       # I/O space mapping
    'ZwMapViewOfSection': 50, # Memory view mapping
    'ZwOpenHandle': 20,       # Handle operations
}

# Special case: WRMSR instruction in .text (max 1 per driver)
WRMSR_POINTS = 20


class DriverAnalyzer:
    """Analyzes Windows drivers for security sinks using idalib."""
    
    def __init__(self):
        self._idalib_initialized = False
        self._idapro = None
        
    def _initialize_idalib(self):
        """Initialize idalib in a thread-safe manner."""
        if self._idalib_initialized:
            return
            
        try:
            import idapro
            self._idapro = idapro
            idapro.enable_console_messages(False)
            self._idalib_initialized = True
            logger.info("idalib initialized successfully")
        except ImportError as e:
            logger.error(f"Failed to import idalib: {e}")
            raise RuntimeError("idalib is required but not available") from e
    
    def analyze_driver(self, driver_path: Path) -> Dict:
        """Analyze a single driver for sinks and IAT information."""
        if not self._idalib_initialized:
            self._initialize_idalib()
            
        try:
            # Open database with auto-analysis
            rc = self._idapro.open_database(str(driver_path), True)
            if rc != 0:
                raise RuntimeError(f"Failed to open database: error code {rc}")
            
            # Wait for auto-analysis to complete
            import ida_auto
            ida_auto.auto_wait()
            
            # Get analysis results
            results = self._extract_analysis_data()
            
            # Close database
            self._idapro.close_database(False)  # Don't save changes
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to analyze {driver_path}: {e}")
            return {
                'file_path': str(driver_path),
                'error': str(e),
                'sinks': [],
                'wrmsr_count': 0,
                'iat_entries': [],
                'score': 0
            }
    
    def _extract_analysis_data(self) -> Dict:
        """Extract sink information and IAT from the loaded database."""
        import idautils
        import ida_funcs
        import ida_name
        import ida_nalt
        import ida_bytes
        import ida_ua
        import ida_segment
        
        # Find .text section
        text_section = None
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            seg_name = ida_segment.get_segm_name(seg)
            if seg_name == '.text' or seg_name == 'PAGE':
                text_section = seg
                break
        
        if not text_section:
            # Fallback to first executable section
            for i in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(i)
                if seg.perm & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    text_section = seg
                    break
        
        if not text_section:
            raise RuntimeError("No executable section found")
        
        # Scan .text for WRMSR instructions
        wrmsr_count = 0
        if text_section:
            current = text_section.start_ea
            end = text_section.end_ea
            while current < end:
                insn = ida_ua.insn_t()
                length = ida_ua.decode_insn(insn, current)
                if length == 0:
                    break
                
                # Check for WRMSR instruction (opcode 0x0F 0x30)
                if current + 1 < end:
                    opcode1 = ida_bytes.get_byte(current)
                    opcode2 = ida_bytes.get_byte(current + 1)
                    if opcode1 == 0x0F and opcode2 == 0x30:
                        wrmsr_count += 1
                
                current += length
        
        # Get IAT entries
        iat_entries = []
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            mod_name = ida_nalt.get_import_module_name(i)
            
            def imp_cb(ea, name, ordinal):
                iat_entries.append({
                    'module': mod_name,
                    'name': name or f"ordinal_{ordinal}",
                    'ordinal': ordinal,
                    'ea': ea
                })
                return True
            
            ida_nalt.enum_import_names(i, imp_cb)
        
        # # Print all IAT imports
        # print(f"  IAT imports:")
        # for entry in iat_entries:
        #     if entry['name'].startswith('ordinal_'):
        #         print(f"    {entry['module']}: {entry['name']} (ordinal {entry['ordinal']})")
        #     else:
        #         print(f"    {entry['module']}: {entry['name']}")
        # print(f"  Total IAT entries: {len(iat_entries)}")
        
        # Find sinks in IAT imports
        sinks_found = []
        for entry in iat_entries:
            func_name = entry['name']
            for sink_name in SINKS.keys():
                if sink_name in func_name:
                    sinks_found.append({
                        'name': sink_name,
                        'function': func_name,
                        'module': entry['module'],
                        'ordinal': entry.get('ordinal', 0)
                    })
        
        # Calculate score
        sink_score = sum(SINKS[sink['name']] for sink in sinks_found)
        # Limit WRMSR to max 1 occurrence for scoring
        wrmsr_score = WRMSR_POINTS if wrmsr_count > 0 else 0
        total_score = sink_score + wrmsr_score
        
        return {
            'file_path': '',
            'sinks': sinks_found,
            'wrmsr_count': wrmsr_count,
            'iat_entries': iat_entries,
            'score': total_score,
            'sink_details': {
                sink['name']: len([s for s in sinks_found if s['name'] == sink['name']])
                for sink in sinks_found
            }
        }


def process_batch(dataset_dir: Path, output_dir: Path) -> List[Dict]:
    """Process all drivers in the dataset directory."""
    # Delete output directory if it exists
    if output_dir.exists():
        import shutil
        logger.info(f"Deleting existing output directory: {output_dir}")
        shutil.rmtree(output_dir)
    
    analyzer = DriverAnalyzer()
    
    # Find all driver files
    driver_files = []
    for ext in ['.sys', '.exe', '.dll']:
        driver_files.extend(dataset_dir.glob(f'*{ext}'))
    
    if not driver_files:
        logger.warning(f"No driver files found in {dataset_dir}")
        return []
    
    logger.info(f"Found {len(driver_files)} driver files to analyze")
    
    # Analyze each driver
    results = []
    for driver_file in driver_files:
        logger.info(f"Analyzing {driver_file.name}...")
        result = analyzer.analyze_driver(driver_file)
        result['file_path'] = str(driver_file)
        results.append(result)
    
    # Sort by score (descending)
    results.sort(key=lambda x: x['score'], reverse=True)
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Rename and copy drivers with priority scores
    for i, result in enumerate(results, 1):
        original_path = Path(result['file_path'])
        new_name = f"{i:03d}_{original_path.name}"
        new_path = output_dir / new_name
        
        # Copy file with new name
        import shutil
        shutil.copy2(original_path, new_path)
        
        # Update result with new path
        result['new_path'] = str(new_path)
        result['priority_rank'] = i
        
        logger.info(f"Rank {i:3d}: {original_path.name} (score: {result['score']}) -> {new_name}")
    
    return results


def save_results(results: List[Dict], output_dir: Path):
    """Save analysis results to JSON file."""
    results_file = output_dir / 'analysis_results.json'
    
    # Create summary
    summary = {
        'total_drivers': len(results),
        'analysis_timestamp': os.times().elapsed,
        'sink_distribution': {},
        'score_stats': {
            'min': min(r['score'] for r in results) if results else 0,
            'max': max(r['score'] for r in results) if results else 0,
            'avg': sum(r['score'] for r in results) / len(results) if results else 0
        },
        'drivers': results
    }
    
    # Count sink occurrences
    for sink_name in SINKS.keys():
        summary['sink_distribution'][sink_name] = sum(
            1 for r in results 
            if any(s['name'] == sink_name for s in r.get('sinks', []))
        )
    
    # Add WRMSR stats
    wrmsr_count = sum(1 for r in results if r.get('wrmsr_count', 0) > 0)
    summary['sink_distribution']['WRMSR'] = wrmsr_count
    
    with open(results_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info(f"Results saved to {results_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze batch of Windows drivers for security sinks'
    )
    parser.add_argument(
        '--dataset-dir',
        type=Path,
        default=Path('../dataset/'),
        help='Directory containing driver files (default: dataset/)'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('sorted_drivers/'),
        help='Output directory for sorted drivers (default: sorted_drivers/)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if not args.dataset_dir.exists():
        logger.error(f"Dataset directory {args.dataset_dir} does not exist")
        sys.exit(1)
    
    logger.info(f"Starting batch analysis of {args.dataset_dir}")
    logger.info(f"Results will be saved to {args.output_dir}")
    
    try:
        results = process_batch(args.dataset_dir, args.output_dir)
        save_results(results, args.output_dir)
        
        logger.info(f"Analysis complete. Processed {len(results)} drivers.")
        
    except Exception as e:
        logger.error(f"Batch processing failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()


