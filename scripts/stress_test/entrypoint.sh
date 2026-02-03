#!/bin/bash
set -e

echo "--- 1. Setting up Firewall Rules ---"

# Flush existing
iptables -F

# STRATEGY CHANGE: 
# 1. NetGuard runs as ROOT (UID 0). We ACCEPT all root traffic immediately.
#    This prevents the loop (NetGuard checking itself) and gives NetGuard full permissions.
iptables -A OUTPUT -m owner --uid-owner 0 -j ACCEPT

# 2. We Queue traffic from the 'stressuser' (UID 1001)
iptables -A OUTPUT -m owner --uid-owner 1001 -p tcp --dport 443 -j NFQUEUE --queue-num 0
iptables -A OUTPUT -m owner --uid-owner 1001 -p tcp --dport 80 -j NFQUEUE --queue-num 0
iptables -A OUTPUT -m owner --uid-owner 1001 -p udp --dport 53 -j NFQUEUE --queue-num 0

echo "--- 2. Starting NetGuard (As Root) ---"
# Start NetGuard in background
./netguard > netguard.log 2>&1 &
NETGUARD_PID=$!

# Stream logs
tail -f netguard.log &
TAIL_PID=$!

# Wait for Engine Hydration (Look for the success message)
echo "Waiting 5s for Engine..."
sleep 5

echo "--- 3. Running Stress Test (As StressUser) ---"
# We run the python script as the constrained user so its traffic gets captured
su -c "python3 traffic_gen.py" stressuser

echo "--- 4. Cleanup ---"
kill $NETGUARD_PID
kill $TAIL_PID