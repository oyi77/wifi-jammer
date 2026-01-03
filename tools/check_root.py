#!/usr/bin/env python3
"""
Quick diagnostic script to check root access and Scapy permissions.
"""

import os
import sys
import platform
import glob

def check_root():
    """Check if running with root privileges."""
    print("=" * 60)
    print("Root Access Diagnostic")
    print("=" * 60)
    
    if platform.system() == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            print(f"Windows Admin: {is_admin}")
            return is_admin
        except (AttributeError, OSError, ImportError):
            print("Could not check Windows admin status")
            return False
    else:
        euid = os.geteuid()
        uid = os.getuid()
        print(f"EUID (Effective User ID): {euid}")
        print(f"UID (Real User ID): {uid}")
        
        if euid == 0:
            print("✅ Running as root (EUID = 0)")
            
            # Check for /dev/bpf* devices on macOS
            if platform.system() == "Darwin":
                bpf_devices = glob.glob("/dev/bpf*")
                print(f"\n/dev/bpf* devices found: {len(bpf_devices)}")
                if bpf_devices:
                    print("✅ /dev/bpf* devices are accessible")
                    for dev in bpf_devices[:5]:  # Show first 5
                        print(f"   - {dev}")
                else:
                    print("⚠️  No /dev/bpf* devices found")
                    print("   This might indicate a system issue")
            
            return True
        else:
            print(f"❌ NOT running as root (EUID = {euid}, need 0)")
            print("\nTo fix: Run with sudo")
            return False

def check_scapy():
    """Check if Scapy can be imported and used."""
    print("\n" + "=" * 60)
    print("Scapy Diagnostic")
    print("=" * 60)
    
    try:
        import scapy
        print("✅ Scapy imported successfully")
        
        # Try to get interfaces using scapy's interface list
        try:
            from scapy.arch.common import get_if_list
            interfaces = get_if_list()
            print(f"✅ Found {len(interfaces)} network interfaces")
            if interfaces:
                print("   Interfaces:", ", ".join(interfaces[:5]))
            else:
                print("   ⚠️  No interfaces found")
        except (AttributeError, ImportError, OSError) as e:
            # Fallback: just confirm scapy is importable
            print(f"⚠️  Could not list interfaces: {e}")
            print("   (Scapy is installed but interface listing failed)")
        
        return True
    except ImportError as e:
        print(f"❌ Scapy not available: {e}")
        print("   Install with: pip install scapy")
        print(f"   Current Python: {sys.executable}")
        return False
    except (OSError, RuntimeError) as e:
        print(f"⚠️  Scapy error: {e}")
        return False

def main():
    """Run all diagnostics."""
    is_root = check_root()
    scapy_ok = check_scapy()
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    
    if is_root and scapy_ok:
        print("✅ All checks passed! You should be able to run attacks.")
    elif is_root and not scapy_ok:
        print("⚠️  Root access OK, but Scapy has issues.")
        print("   Install Scapy: pip install scapy")
    elif not is_root and scapy_ok:
        print("❌ Scapy OK, but need root privileges.")
        print("   Run with: sudo python3 tools/check_root.py")
    else:
        print("❌ Both root access and Scapy have issues.")
    
    return 0 if (is_root and scapy_ok) else 1

if __name__ == "__main__":
    sys.exit(main())

