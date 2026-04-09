import os
import sys
import time
import threading
import shutil
from harvest import run_harvest
from app import app

def start_project():
    # --- PRE-FLIGHT CLEANUP (first run clean start) ---
    # Wipe previous session data so harvest starts fresh
    # Safe: harvest.py will restore from DB if harvest fails
    print("🧹 NetGuard v6.0 — cleaning previous session data...")
    import shutil
    if os.path.exists('network_configs'):
        shutil.rmtree('network_configs')
    os.makedirs('network_configs', exist_ok=True)
    if os.path.exists('topology.json'):
        os.remove('topology.json')
    print("✅ Clean slate — ready for fresh harvest")

    # Phase 1: Recursive Network Discovery
    print("\n" + "="*60)
    print("🚀 PHASE 1: ENTERPRISE NETWORK HARVESTING")
    print("   Target: Discovering Routers, Switches, and End-Hosts")
    print("   Mode: GNS3-Safe (Sequential Scanning)")
    print("="*60)
    
    try:
        run_harvest()
    except KeyboardInterrupt:
        print("\n[!] Harvest interrupted by user. Moving to Dashboard...")
    except Exception as e:
        print(f"❌ Critical error during harvesting: {e}")
        sys.exit(1)

    # Phase 2: Start the Security Dashboard
    print("\n" + "="*60)
    print("🚀 PHASE 2: LAUNCHING SECURITY DASHBOARD")
    print("   Analyzing configurations for vulnerabilities...")
    print("="*60)

    def notify_ready():
        """Just print the ready message — launcher opens the browser."""
        time.sleep(3)
        print(f"\n>>> 🌐 DASHBOARD READY: http://127.0.0.1:5000")
        print(">>> 📋 Audit Report generated for all discovered nodes.")
        print(">>> 🛑 Press Ctrl+C to stop the system\n")

    threading.Thread(target=notify_ready, daemon=True).start()
    
    # Run Flask
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[!] System shut down. All audit files saved in /network_configs/")
    except Exception as e:
        print(f"❌ Server Error: {e}")

if __name__ == "__main__":
    start_project()
