#!/usr/bin/env python3
"""
Integration with LPE-finder Analysis Pipeline

This module provides integration between the harness and the existing
LPE-finder analysis pipeline, allowing the batch-processed drivers
to be analyzed using the full AI-powered analysis workflow.
"""

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

from .process_batch import DriverAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class LPEFinderIntegration:
    """Integrates harness with the LPE-finder analysis pipeline."""
    
    def __init__(self, lpe_finder_path: Path):
        self.lpe_finder_path = lpe_finder_path
        self.analysis_runner = lpe_finder_path / "analysis" / "runner.py"
        
        if not self.analysis_runner.exists():
            raise FileNotFoundError(f"LPE-finder runner not found at {self.analysis_runner}")
    
    def run_single_driver_analysis(
        self, 
        driver_path: Path, 
        memory_dump_path: Optional[Path] = None,
        output_dir: Optional[Path] = None
    ) -> Dict:
        """Run LPE-finder analysis on a single driver."""
        if not driver_path.exists():
            raise FileNotFoundError(f"Driver not found: {driver_path}")
        
        # Build command
        cmd = [
            sys.executable, 
            str(self.analysis_runner),
            "--target", str(driver_path)
        ]
        
        if memory_dump_path and memory_dump_path.exists():
            cmd.extend(["--memory-dump", str(memory_dump_path)])
        
        if output_dir:
            cmd.extend(["--emit-findings", str(output_dir)])
        
        logger.info(f"Running LPE-finder analysis: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            if result.returncode == 0:
                logger.info(f"Analysis completed successfully for {driver_path.name}")
                return {
                    'success': True,
                    'driver': driver_path.name,
                    'output': result.stdout,
                    'errors': result.stderr
                }
            else:
                logger.error(f"Analysis failed for {driver_path.name}")
                logger.error(f"Error: {result.stderr}")
                return {
                    'success': False,
                    'driver': driver_path.name,
                    'output': result.stdout,
                    'errors': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            logger.error(f"Analysis timed out for {driver_path.name}")
            return {
                'success': False,
                'driver': driver_path.name,
                'output': "",
                'errors': "Analysis timed out after 1 hour"
            }
        except Exception as e:
            logger.error(f"Analysis failed with exception for {driver_path.name}: {e}")
            return {
                'success': False,
                'driver': driver_path.name,
                'output': "",
                'errors': str(e)
            }
    
    def run_batch_analysis(
        self, 
        sorted_drivers_dir: Path, 
        results_dir: Path,
        memory_dumps_dir: Optional[Path] = None
    ) -> List[Dict]:
        """Run LPE-finder analysis on all sorted drivers."""
        if not sorted_drivers_dir.exists():
            raise FileNotFoundError(f"Sorted drivers directory not found: {sorted_drivers_dir}")
        
        results_dir.mkdir(parents=True, exist_ok=True)
        
        # Get all driver files, sorted by priority (001_*, 002_*, etc.)
        driver_files = sorted(sorted_drivers_dir.glob('*.sys'))
        
        if not driver_files:
            logger.warning(f"No driver files found in {sorted_drivers_dir}")
            return []
        
        logger.info(f"Starting batch analysis of {len(driver_files)} drivers")
        
        results = []
        for i, driver_file in enumerate(driver_files, 1):
            logger.info(f"Analyzing driver {i}/{len(driver_files)}: {driver_file.name}")
            
            # Find corresponding memory dump if available
            memory_dump = None
            if memory_dumps_dir and memory_dumps_dir.exists():
                dump_file = memory_dumps_dir / f"{driver_file.stem}.dmp"
                if dump_file.exists():
                    memory_dump = dump_file
            
            # Run analysis
            driver_results_dir = results_dir / driver_file.stem
            result = self.run_single_driver_analysis(
                driver_file, 
                memory_dump, 
                driver_results_dir
            )
            
            results.append(result)
            
            # Save individual result
            result_file = results_dir / f"{driver_file.stem}_lpe_result.json"
            with open(result_file, 'w') as f:
                json.dump(result, f, indent=2)
        
        # Save summary
        summary = {
            'total_drivers': len(driver_files),
            'successful_analyses': sum(1 for r in results if r['success']),
            'failed_analyses': sum(1 for r in results if not r['success']),
            'results': results
        }
        
        summary_file = results_dir / 'lpe_finder_batch_summary.json'
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Batch analysis completed. Results saved to {results_dir}")
        return results


def main():
    parser = argparse.ArgumentParser(
        description='Integrate harness with LPE-finder analysis pipeline'
    )
    parser.add_argument(
        '--lpe-finder-path',
        type=Path,
        default=Path('.'),
        help='Path to LPE-finder repository (default: current directory)'
    )
    parser.add_argument(
        '--sorted-drivers',
        type=Path,
        default=Path('sorted_drivers/'),
        help='Directory containing sorted driver files (default: sorted_drivers/)'
    )
    parser.add_argument(
        '--results-dir',
        type=Path,
        default=Path('lpe_finder_results/'),
        help='Output directory for LPE-finder results (default: lpe_finder_results/)'
    )
    parser.add_argument(
        '--memory-dumps',
        type=Path,
        help='Directory containing memory dumps for drivers'
    )
    parser.add_argument(
        '--single-driver',
        type=Path,
        help='Analyze a single driver file'
    )
    parser.add_argument(
        '--memory-dump',
        type=Path,
        help='Memory dump file for single driver analysis'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize integration
        integration = LPEFinderIntegration(args.lpe_finder_path)
        
        if args.single_driver:
            # Single driver analysis
            if not args.single_driver.exists():
                logger.error(f"Driver file not found: {args.single_driver}")
                sys.exit(1)
            
            logger.info(f"Analyzing single driver: {args.single_driver.name}")
            
            result = integration.run_single_driver_analysis(
                args.single_driver,
                args.memory_dump,
                args.results_dir
            )
            
            if result['success']:
                logger.info("Single driver analysis completed successfully")
            else:
                logger.error("Single driver analysis failed")
                logger.error(f"Errors: {result['errors']}")
                sys.exit(1)
        
        else:
            # Batch analysis
            results = integration.run_batch_analysis(
                args.sorted_drivers,
                args.results_dir,
                args.memory_dumps
            )
            
            successful = sum(1 for r in results if r['success'])
            failed = len(results) - successful
            
            logger.info(f"Batch analysis completed:")
            logger.info(f"  Total drivers: {len(results)}")
            logger.info(f"  Successful: {successful}")
            logger.info(f"  Failed: {failed}")
            
            if failed > 0:
                logger.warning("Some analyses failed. Check individual result files for details.")
    
    except Exception as e:
        logger.error(f"Integration failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()


