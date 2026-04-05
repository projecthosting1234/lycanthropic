#!/usr/bin/env python3
"""
Driver Analysis Runner

This script automates the analysis of Windows drivers in a Hyper-V VM.
It manages VM snapshots, transfers drivers, loads them, dumps memory using
WinDbg (via pykd), and runs the AI analysis pipeline.

Usage:
    python runner.py --sorted-dir sorted_drivers/ --vm-name "Windows VM"

Workflow:
1. Create/restore snapshot (clean state)
2. Connect to VM via WinDbg (kdnet)
3. Transfer driver to VM via SSH
4. Load driver in VM
5. Dump memory using WinDbg .dump command
6. Restore to snapshot
7. Run AI analysis with memory dump + driver binary
8. Repeat for all drivers
"""

import argparse
import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import paramiko

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WinDbgManager:
    """Manages WinDbg connection and memory dumps using pykd."""

    def __init__(
        self,
        debugger_path: str,
        connection_string: str,
        dump_type: str = "mini",
        local_dump_dir: str = "C:\\Users\\legitdev\\Downloads\\windows-defender-remover-main"
    ):
        self.debugger_path = debugger_path
        self.connection_string = connection_string
        self.dump_type = dump_type  # "full" or "mini"
        self.local_dump_dir = Path(local_dump_dir)
        self._pykd = None
        self._connected = False

        # Ensure local dump directory exists
        self.local_dump_dir.mkdir(parents=True, exist_ok=True)

    def initialize(self) -> bool:
        """Initialize pykd and add DLL directory."""
        try:
            # Add debugger path to DLL search path
            if os.path.isdir(self.debugger_path):
                os.add_dll_directory(self.debugger_path)
                os.environ["PATH"] = self.debugger_path + ";" + os.environ.get("PATH", "")

            import pykd
            pykd.initialize()
            self._pykd = pykd
            logger.info(f"pykd initialized (debugger: {self.debugger_path})")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize pykd: {e}")
            return False

    def connect(self, timeout_ms: int = 120000) -> bool:
        """Connect to kernel debug target via kdnet.

        Args:
            timeout_ms: Timeout in milliseconds for connection

        Returns:
            True if connected successfully
        """
        if self._pykd is None:
            if not self.initialize():
                return False

        try:
            # Set initial breakpoint exception to enabled
            self._pykd.dbgCommand("sxe ibp")

            # Connect via kdnet
            logger.info(f"Connecting to kernel target: {self.connection_string}")
            self._pykd.attachKernel(self.connection_string)

            # Wait for the target to break in
            logger.info("Waiting for target to break in...")
            self._pykd.go()  # blocks until initial breakpoint fires

            # Verify connection
            output = self._pykd.dbgCommand("vertarget")
            if "Windows" in output:
                logger.info(f"Connected: {output.strip().split(chr(10))[0][:100]}")
                self._connected = True
                return True
            else:
                logger.warning(f"Connected but vertarget unexpected: {output[:200]}")
                self._connected = True
                return True

        except Exception as e:
            logger.error(f"Failed to connect to kernel target: {e}")
            return False

    def disconnect(self) -> bool:
        """Disconnect from the kernel debug target."""
        if self._pykd is not None and self._connected:
            try:
                self._pykd.detachAllProcesses()
                self._connected = False
                logger.info("Disconnected from kernel target")
                return True
            except Exception as e:
                logger.warning(f"Error during disconnect: {e}")
                return False
        return True

    def dump_memory(self, output_filename: str) -> Tuple[bool, str]:
        """Create a memory dump using WinDbg .dump command.

        Args:
            output_filename: Name of the dump file (without path)

        Returns:
            Tuple of (success, local_path)
        """
        if not self._connected or self._pykd is None:
            return False, "Not connected to kernel target"

        try:
            # Build the .dump command
            dump_path = self.local_dump_dir / output_filename

            if self.dump_type == "full":
                # Full kernel dump
                cmd = f".dump /f /o \"{dump_path}\""
            else:
                # Mini dump (kernel memory only)
                cmd = f".dump /m /o \"{dump_path}\""

            logger.info(f"Creating memory dump: {dump_path}")
            output = self._pykd.dbgCommand(cmd)

            # Check if dump was created
            if "Dump successfully written" in output or "created" in output.lower():
                logger.info(f"Memory dump created: {dump_path}")
                return True, str(dump_path)
            else:
                logger.error(f"Failed to create dump: {output}")
                return False, f"Dump failed: {output}"

        except Exception as e:
            logger.error(f"Exception during memory dump: {e}")
            return False, str(e)

    def execute_command(self, command: str) -> Tuple[bool, str]:
        """Execute a WinDbg command.

        Args:
            command: WinDbg command to execute

        Returns:
            Tuple of (success, output)
        """
        if not self._connected or self._pykd is None:
            return False, "Not connected"

        try:
            output = self._pykd.dbgCommand(command)
            return True, output
        except Exception as e:
            return False, str(e)

    def is_connected(self) -> bool:
        """Check if connected to kernel target."""
        return self._connected


class HyperVManager:
    """Manages Hyper-V VM operations using PowerShell."""
    
    def __init__(self, vm_name: str):
        self.vm_name = vm_name
        self.snapshot_name = "clean_state"
    
    def _run_powershell(self, args: List[str], timeout: int = 120) -> Tuple[bool, str]:
        """Run PowerShell command and return success status and output."""
        try:
            cmd = ['powershell', '-NoProfile', '-Command'] + args
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            # PowerShell returns exit code 0 even on some errors, check output
            if result.returncode != 0 or "error" in result.stdout.lower():
                logger.error(f"PowerShell command failed: {' '.join(args)}")
                logger.error(f"Output: {result.stdout}")
                logger.error(f"Stderr: {result.stderr}")
                return False, result.stdout + result.stderr
            return True, result.stdout
        except subprocess.TimeoutExpired:
            logger.error(f"PowerShell command timed out: {' '.join(args)}")
            return False, "Timeout"
        except Exception as e:
            logger.error(f"PowerShell command failed: {' '.join(args)}")
            logger.error(f"Error: {e}")
            return False, str(e)
    
    def vm_exists(self) -> bool:
        """Check if the VM exists."""
        success, output = self._run_powershell([
            f"Get-VM -Name '{self.vm_name}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"
        ])
        return success and self.vm_name.lower() in output.lower()
    
    def is_running(self) -> bool:
        """Check if the VM is currently running."""
        success, output = self._run_powershell([
            f"Get-VM -Name '{self.vm_name}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty State"
        ])
        return success and "running" in output.lower()
    
    def start_vm(self, timeout: int = 60) -> bool:
        """Start the VM."""
        if self.is_running():
            logger.info(f"VM {self.vm_name} is already running")
            return True
        
        logger.info(f"Starting VM {self.vm_name}...")
        success, output = self._run_powershell([
            f"Start-VM -Name '{self.vm_name}'"
        ], timeout=timeout)
        
        if success:
            logger.info("VM started successfully")
            # Wait for VM to boot
            time.sleep(15)
            return True
        else:
            logger.error(f"Failed to start VM: {output}")
            return False
    
    def stop_vm(self, timeout: int = 120) -> bool:
        """Stop the VM gracefully using Hyper-V shutdown."""
        if not self.is_running():
            logger.info(f"VM {self.vm_name} is not running")
            return True
        
        logger.info(f"Stopping VM {self.vm_name}...")
        # Try graceful shutdown first using Hyper-V's shutdown action
        success, output = self._run_powershell([
            f"Stop-VM -Name '{self.vm_name}' -Force"
        ], timeout=timeout)
        
        if success:
            logger.info("VM shutdown initiated")
            # Wait for VM to stop
            for _ in range(60):
                if not self.is_running():
                    break
                time.sleep(2)
            else:
                logger.warning("VM did not shut down gracefully")
            return True
        else:
            logger.error(f"Failed to stop VM: {output}")
            return False
    
    def create_snapshot(self) -> bool:
        """Create a clean state checkpoint (snapshot)."""
        logger.info(f"Creating checkpoint '{self.snapshot_name}'...")
        success, output = self._run_powershell([
            f"Checkpoint-VM -Name '{self.vm_name}' -SnapshotName '{self.snapshot_name}'"
        ])
        
        if success:
            logger.info(f"Checkpoint '{self.snapshot_name}' created successfully")
            return True
        else:
            logger.error(f"Failed to create checkpoint: {output}")
            return False
    
    def snapshot_exists(self) -> bool:
        """Check if the checkpoint exists."""
        success, output = self._run_powershell([
            f"Get-VMSnapshot -VMName '{self.vm_name}' -Name '{self.snapshot_name}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"
        ])
        return success and self.snapshot_name.lower() in output.lower()
    
    def restore_snapshot(self, force_restore: bool = False) -> bool:
        """Restore the clean state checkpoint, creating it if it doesn't exist.
        
        Args:
            force_restore: If True, always restore the checkpoint even if it was just created.
        """
        # Check if snapshot exists, if not create it
        snapshot_just_created = False
        if not self.snapshot_exists():
            logger.info(f"Checkpoint '{self.snapshot_name}' does not exist. Creating it...")
            # Need to start VM first to take a checkpoint
            if not self.is_running():
                if not self.start_vm():
                    logger.error("Failed to start VM to create checkpoint")
                    return False
            
            # Now create the checkpoint
            if not self.create_snapshot():
                logger.error("Failed to create checkpoint")
                return False
            
            snapshot_just_created = True
        
        # Don't restore if we just created the snapshot (VM is already in clean state)
        if snapshot_just_created and not force_restore:
            logger.info("Checkpoint created, VM is already in clean state")
            return True

        # Hyper-V supports live revert - no need to stop VM before restoring
        logger.info(f"Restoring checkpoint '{self.snapshot_name}' (live revert)...")
        success, output = self._run_powershell([
            f"Restore-VMSnapshot -Name '{self.snapshot_name}' -VMName '{self.vm_name}' -Confirm:$false"
        ])


        # Wait for VM to be ready after live revert
        time.sleep(10)
        
        if success:
            logger.info(f"Checkpoint '{self.snapshot_name}' restored successfully")
            return True
        else:
            logger.error(f"Failed to restore checkpoint: {output}")
            return False


class SSHManager:
    """Manages SSH connections to the VM."""
    
    def __init__(self, hostname: str, username: str, password: str, timeout: int, port: int = 22):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.port = port
        self.client: Optional[paramiko.SSHClient] = None
    
    def connect(self) -> bool:
        """Connect to the VM via SSH."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            logger.info(f"Connecting to {self.hostname}:{self.port} as {self.username}")
            self.client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            
            logger.info("SSH connection established")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect via SSH: {e}")
            return False
    
    def disconnect(self):
        """Disconnect SSH client."""
        if self.client:
            self.client.close()
            self.client = None
    
    def execute_command(self, command: str, timeout: int = 60) -> Tuple[bool, str, str]:
        """Execute a command on the remote VM."""
        if not self.client:
            return False, "", "Not connected"
        
        try:
            logger.debug(f"Executing: {command}")
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            
            stdout_text = stdout.read().decode('utf-8', errors='ignore')
            stderr_text = stderr.read().decode('utf-8', errors='ignore')
            
            return True, stdout_text, stderr_text
            
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return False, "", str(e)
    
    def transfer_file(self, local_path: Path, remote_path: str) -> bool:
        """Transfer a file to the remote VM."""
        if not self.client:
            return False
        
        try:
            sftp = self.client.open_sftp()
            logger.info(f"Transferring {local_path} to {remote_path}")
            sftp.put(str(local_path), remote_path)
            sftp.close()
            logger.info("File transfer completed")
            return True
            
        except Exception as e:
            logger.error(f"File transfer failed: {e}")
            return False


class DriverLoader:
    """Handles driver loading in the VM."""
    
    def __init__(self, ssh: SSHManager):
        self.ssh = ssh
        self.driver_dir = "C:\\Drivers\\"
    
    def setup_directories(self) -> bool:
        """Create necessary directories on the VM."""
        commands = [
            f"mkdir {self.driver_dir}"
        ]
        
        for cmd in commands:
            success, stdout, stderr = self.ssh.execute_command(cmd)
            if not success:
                logger.error(f"Failed to create directory: {cmd}")
                return False
        
        return True
    
    def load_driver(self, driver_name: str) -> Tuple[bool, str]:
        """Load a driver in the VM using sc.exe."""
        # Stop driver if already running
        stop_cmd = f"sc.exe stop {driver_name}"
        self.ssh.execute_command(stop_cmd)
        
        # Delete service if exists
        delete_cmd = f"sc.exe delete {driver_name}"
        self.ssh.execute_command(delete_cmd)
        
        # Create and start service in one command
        load_cmd = f"sc.exe create {driver_name} binPath= C:\\windows\\temp\\{driver_name}.sys type=kernel && sc.exe start {driver_name}"
        success, stdout, stderr = self.ssh.execute_command(load_cmd)
        
        if not success:
            return False, f"Failed to load driver: {stderr}"
        
        # Wait for driver to load
        time.sleep(2)
        
        return True, "Driver loaded successfully"
    
    def unload_driver(self, driver_name: str) -> bool:
        """Unload driver and clean up."""
        # Stop service
        stop_cmd = f"sc stop {driver_name}"
        self.ssh.execute_command(stop_cmd)
        
        # Delete service
        delete_cmd = f"sc delete {driver_name}"
        self.ssh.execute_command(delete_cmd)
        
        return True


class AnalysisOrchestrator:
    """Orchestrates the entire analysis pipeline."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.hyperv = HyperVManager(config['vm_name'])
        self.ssh = SSHManager(
            config['ssh_hostname'],
            config['ssh_username'], 
            config['ssh_password'],
            config['vm_boot_timeout'],
            config.get('ssh_port', 22)
        )
        self.loader = DriverLoader(self.ssh)
        
        # WinDbg configuration from config
        windbg_config = config.get('windbg', {})
        self.windbg = WinDbgManager(
            debugger_path=windbg_config.get('debugger_path', "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64"),
            connection_string=windbg_config.get('connection_string', 'net:port=50000,key=a1.b2.c3.d4'),
            dump_type=windbg_config.get('dump_type', 'full'),
            local_dump_dir=windbg_config.get('local_dump_dir', "C:\\Dumps")
        )
        
        # Paths
        self.sorted_dir = Path(config['sorted_dir'])
        self.results_dir = Path(config.get('results_dir', 'analysis_results/'))
        self.results_dir.mkdir(exist_ok=True)
        
        # Batch size - how many drivers to process before restoring snapshot
        self.batch_size = config.get('batch_size', 1)
    
    async def run_analysis(self):
        """Run the complete analysis pipeline."""
        logger.info("Starting driver analysis pipeline")
        
        # Validate VM
        if not self.hyperv.vm_exists():
            logger.error(f"VM {self.hyperv.vm_name} does not exist")
            return
        
        # start from clean state
        if not self.hyperv.restore_snapshot():
            logger.error("Failed to restore clean state")
            return
        
        if not self.hyperv.start_vm():
            logger.error("Failed to start vm")
            return 
        
        # Connect SSH for driver transfer
        if not self.ssh.connect():
            logger.error("Failed to connect to VM via SSH")
            self.windbg.disconnect()
            self.hyperv.stop_vm()
            return
        
        try:
            # Setup directories
            if not self.loader.setup_directories():
                logger.error("Failed to setup directories on VM")
                return
            
            # Get list of drivers to analyze
            driver_files = list(self.sorted_dir.glob('*.sys'))
            if not driver_files:
                logger.warning(f"No driver files found in {self.sorted_dir}")
                return
            
            logger.info(f"Found {len(driver_files)} drivers to analyze")
            logger.info(f"Batch size: {self.batch_size}")
            
            # NOTE: We could process drivers in batches here
            # total_drivers = len(driver_files)
            for driver_file in driver_files:
                try:
                    # Restore clean state (live revert - VM stays running)
                    if not self.hyperv.restore_snapshot():
                        logger.error("Failed to restore clean state")
                        break

                    # Reconnect SSH after checkpoint restore
                    if not self.ssh.connect():
                        logger.error("Failed to reconnect to VM via SSH after checkpoint restore")
                        break

                    # Step 1: Transfer all drivers in the batch
                
                    remote_path = f"{self.loader.driver_dir}{driver_file.name}"
                    if not self.ssh.transfer_file(driver_file, remote_path):
                        logger.error(f"Failed to transfer {driver_file.name}")
                
                    # Step 2: Load all drivers in the batch
                    driver_name = driver_file.stem
                    success, msg = self.loader.load_driver(driver_name)
                    if success:
                        logger.info(f"Loaded driver: {driver_name}")
                    else:
                        logger.error(f"Failed to load {driver_name}: {msg}")
                    
                    # Step 3: Dump memory for all loaded drivers using WinDbg
                    try:
                        # Use WinDbg .dump command
                        # Connect to WinDbg (this will wait for the VM to boot and break in)
                        if not self.windbg.connect():
                            logger.error("Failed to connect to WinDbg")
                            self.hyperv.stop_vm()
                            return

                        dump_filename = f"{driver_name}.dmp"
                        success, dump_path = self.windbg.dump_memory(
                            dump_filename
                        )
                        
                        if not self.windbg.disconnect():
                            logger.error("Failed to DISCONNECT from WinDbg")
                            self.hyperv.stop_vm()
                            return

                        if not success:
                            logger.error(f"Failed to dump memory for {driver_name}: {dump_path}")
                            continue
                        
                        # Run AI analysis
                        await self.run_ai_analysis(driver_file, dump_path)
                        logger.info(f"Completed analysis for {driver_name}")
                        
                    except Exception as e:
                        logger.error(f"Error processing memory dump for {driver_name}: {e}")
                    finally:
                        # Unload driver
                        self.loader.unload_driver(driver_name)
                    
                except Exception as e:
                    logger.error(f"Error processing batch: {e}")
                    continue
        
        finally:
            self.ssh.disconnect()
            self.windbg.disconnect()
            self.hyperv.stop_vm()
    
    async def run_ai_analysis(self, driver_file: Path, memory_dump: Path):
        """Run the AI analysis pipeline with driver and memory dump."""
        # Import the Windows symbols hook
        try:
            from harness.win_symbols_builder import build_windows_symbols_hook
            pre_smt_callbacks = [build_windows_symbols_hook]
            logger.info("Windows symbols pre-SMT hook enabled for analysis")
        except ImportError as e:
            logger.warning(f"Failed to import Windows symbols hook: {e}")
            pre_smt_callbacks = []

        # Run the analysis pipeline with the driver and memory dump
        # This would integrate with the existing analysis pipeline
        logger.info(f"Running AI analysis for {driver_file.name} with memory dump {memory_dump}")
        
        # For now, create a placeholder result
        result = {
            'driver': driver_file.name,
            'memory_dump': str(memory_dump),
            'analysis_timestamp': time.time(),
            'status': 'completed',
            'pre_smt_callbacks_enabled': len(pre_smt_callbacks) > 0
        }
        
        result_file = self.results_dir / f"{driver_file.stem}_result.json"
        with open(result_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        # Here you would normally call the actual analysis pipeline
        # For example:
        # from analysis.run_all_passes import run_smt_all
        # smt_results = run_smt_all(
        #     findings_dir=Path("findings_out") / driver_file.name,
        #     pre_smt_callbacks=pre_smt_callbacks
        # )


def load_config(config_path: Path) -> Dict:
    """Load configuration from JSON file."""
    if not config_path.exists():
        logger.error(f"Configuration file {config_path} does not exist")
        sys.exit(1)
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # Return the harness section from root config.json, or full config if not found
    if "harness" in config:
        return config["harness"]
    return config



def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    parser = argparse.ArgumentParser(
        description='Automate driver analysis in Hyper-V VM with WinDbg'
    )
    parser.add_argument(
        '--sorted-dir',
        type=Path,
        default=Path('sorted_drivers/'),
        help='Directory containing sorted driver files (default: sorted_drivers/)'
    )
    parser.add_argument(
        '--config',
        type=Path,
        default=Path('../config.json'),
        help='Configuration file path (default: ../config.json)'
    )

    parser.add_argument(
        '--vm-name',
        type=str,
        help='Hyper-V VM name (overrides config file)'
    )
    parser.add_argument(
        '--ssh-host',
        type=str,
        help='SSH hostname (overrides config file)'
    )
    parser.add_argument(
        '--ssh-user',
        type=str,
        help='SSH username (overrides config file)'
    )
    parser.add_argument(
        '--ssh-pass',
        type=str,
        help='SSH password (overrides config file)'
    )
    parser.add_argument(
        '--windbg-connection',
        type=str,
        help='WinDbg connection string (overrides config file, e.g., net:port=50000,key=a1.b2.c3.d4)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    config = load_config(args.config)
    
    # Override config with command line arguments
    if args.vm_name:
        config['vm_name'] = args.vm_name
    if args.ssh_host:
        config['ssh_hostname'] = args.ssh_host
    if args.ssh_user:
        config['ssh_username'] = args.ssh_user
    if args.ssh_pass:
        config['ssh_password'] = args.ssh_pass
    if args.windbg_connection:
        if 'windbg' not in config:
            config['windbg'] = {}
        config['windbg']['connection_string'] = args.windbg_connection
    
    # Validate required config
    required_fields = ['vm_name', 'ssh_hostname', 'ssh_username', 'ssh_password']
    for field in required_fields:
        if field not in config:
            logger.error(f"Missing required configuration field: {field}")
            sys.exit(1)
    
    # Validate WinDbg config
    if 'windbg' not in config:
        logger.warning("No WinDbg configuration found, using defaults")
        config['windbg'] = {
            'debugger_path': "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64",
            'connection_string': 'net:port=50000,key=a1.b2.c3.d4',
            'dump_type': 'full',
            'local_dump_dir': "C:\\Dumps"
        }
    
    # Update sorted directory if provided
    config['sorted_dir'] = str(args.sorted_dir)

    # Run analysis
    orchestrator = AnalysisOrchestrator(config)
    asyncio.run(orchestrator.run_analysis())
    
    logger.info("Analysis pipeline completed")


if __name__ == '__main__':
    main()
