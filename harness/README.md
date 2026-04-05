# Driver Analysis Harness

This directory contains automation scripts for batch processing Windows drivers using the LPE-finder analysis pipeline.

## Overview

The harness consists of two main components:

1. **`process_batch.py`** - Analyzes drivers and ranks them by vulnerability potential
2. **`runner.py`** - Automates VM-based analysis with memory dumping and AI analysis

## Prerequisites

### Required Software
- **IDA Pro** with idalib API (for driver analysis)
- **VirtualBox** (for VM automation)
- **Python 3.8+** with required packages:
  ```bash
  pip install paramiko tqdm
  ```

### VM Setup
1. Create a Windows VM in VirtualBox
2. Install SSH server (OpenSSH)
3. Configure network for SSH access
4. Install necessary tools for driver loading and memory dumping

## Usage

### Step 1: Batch Processing

Analyze drivers and rank them by security sink presence:

```bash
# Basic usage
python harness/process_batch.py --dataset-dir dataset/ --output-dir sorted_drivers/

# Verbose output
python harness/process_batch.py --dataset-dir dataset/ --output-dir sorted_drivers/ --verbose
```

This will:
- Load each driver using idalib
- Parse Import Address Table (IAT)
- Scan .text section for security sinks
- Rank drivers by vulnerability potential
- Rename drivers with priority scores (001_highest.sys, 002_second.sys, etc.)

### Step 2: VM-based Analysis

Automate driver analysis in a VirtualBox VM:

```bash
# Basic usage with config file
python harness/runner.py --sorted-dir sorted_drivers/

# Override config with command line arguments
python harness/runner.py --vm-name "My Windows VM" --ssh-host 192.168.1.100 --ssh-user admin --ssh-pass password

# Create clean state snapshot
python harness/runner.py --create-snapshot
```

## Configuration

Edit `harness_config.json` to configure your environment:

```json
{
  "vm_name": "Windows Driver Analysis VM",
  "ssh_hostname": "192.168.56.101",
  "ssh_username": "administrator", 
  "ssh_password": "your_password_here",
  "ssh_port": 22,
  "sorted_dir": "sorted_drivers/",
  "results_dir": "analysis_results/"
}
```

## Sink Scoring System

Drivers are scored based on security-relevant sinks:

| Sink | Points | Description |
|------|--------|-------------|
| `MmMapIoSpace` | 50 | I/O space mapping |
| `ZwMapViewOfSection` | 50 | Memory view mapping |
| `ZwOpenHandle` | 20 | Handle operations |
| `WriteMsr` | 20 | MSR write operations |
| `WRMSR instruction` | 20 | Assembly WRMSR (max 1 per driver) |

## Workflow

### Batch Processing (`process_batch.py`)
1. Load each driver using idalib (same logic as `ida_mcp`)
2. Parse Import Address Table (IAT)
3. Scan .text section for WRMSR instructions
4. Find functions containing sink names
5. Calculate vulnerability score
6. Sort drivers by score (highest first)
7. Rename with priority prefixes

### VM Analysis (`runner.py`)
1. Start VM and restore clean snapshot
2. Transfer driver to VM via SSH
3. Load driver using `sc.exe`
4. Dump driver memory using livekd
5. Transfer memory dump back to host
6. Unload driver and restore snapshot
7. Run AI analysis with driver + memory dump
8. Repeat for all drivers

## Output

### Batch Processing
- `sorted_drivers/` - Renamed drivers with priority scores
- `analysis_results.json` - Detailed analysis results

### VM Analysis
- `analysis_results/` - Individual analysis results per driver
- Memory dumps for each analyzed driver
- Integration with existing AI analysis pipeline

## Integration with LPE-finder

The harness integrates with the existing LPE-finder analysis pipeline:

1. **Driver Ranking**: Uses the same idalib-based analysis as `ida_mcp`
2. **Memory Analysis**: Provides memory dumps for dynamic analysis
3. **AI Pipeline**: Feeds results into the existing constraint and SMT analysis

## Troubleshooting

### Common Issues

1. **IDA Pro not found**: Ensure IDA Pro is installed and idalib is accessible
2. **VM not accessible**: Check VirtualBox installation and VM network configuration
3. **SSH connection failed**: Verify SSH server is running and credentials are correct
4. **Driver loading failed**: Ensure VM has proper driver loading permissions

### Debug Mode

Use `--verbose` flag for detailed logging:

```bash
python harness/process_batch.py --verbose
python harness/runner.py --verbose
```

## Security Notes

- Store SSH passwords securely (consider using SSH keys)
- Ensure VM is properly isolated for driver testing
- Monitor VM for stability during driver loading
- Use snapshots to maintain clean state between tests