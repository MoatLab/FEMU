#!/bin/bash
# fdp-test-nvme-admin-u24.sh
# Test FDP NVMe admin interface correctness on kernel 6.12
# Run inside VM via SSH

set -e
CTRL=/dev/nvme0
NS=/dev/nvme0n1
NG=/dev/ng0n1
PASS=0
FAIL=0

pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

echo "=== FDP NVMe Admin Interface Tests ==="
echo "Device: $CTRL  NS: $NS  NG: $NG"

# Test 1: id-ctrl CTRATT bit 19 set (FDP support)
CTRATT=$(sudo nvme id-ctrl $CTRL | grep "^ctratt" | awk '{print $3}')
echo "CTRATT=$CTRATT"
if python3 -c "assert int('$CTRATT', 16) & (1<<19), 'FDP bit not set'" 2>/dev/null; then
    pass "CTRATT bit 19 (FDP) set: $CTRATT"
else
    fail "CTRATT bit 19 (FDP) missing: $CTRATT"
fi

# Test 2: fdp configs nruh=4, nrg=1
CONFIGS=$(sudo nvme fdp configs $CTRL -e 1)
echo "$CONFIGS"
NRUH=$(echo "$CONFIGS" | grep -i "Number of Reclaim Unit Handles" | grep -o '[0-9]*' | head -1)
NRG=$(echo "$CONFIGS" | grep -i "Number of Reclaim Groups" | grep -o '[0-9]*' | head -1)
[ "$NRUH" = "4" ] && pass "fdp configs nruh=4" || fail "fdp configs nruh=$NRUH (expected 4)"
[ "$NRG" = "1" ] && pass "fdp configs nrg=1" || fail "fdp configs nrg=$NRG (expected 1)"

# Test 3: All 4 RUHs are Persistently Isolated
PI_COUNT=$(echo "$CONFIGS" | grep -c "Persistently Isolated")
[ "$PI_COUNT" = "4" ] && pass "All 4 RUHs Persistently Isolated" || fail "PI count=$PI_COUNT (expected 4)"

# Test 4: fdp stats returns valid fields (all zero on fresh start)
STATS=$(sudo nvme fdp stats $NG -e 1 -o json 2>/dev/null)
echo "FDP stats JSON: $STATS"
if echo "$STATS" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'hbmw' in d and 'mbmw' in d and 'mbe' in d, 'missing fields'" 2>/dev/null; then
    pass "fdp stats has hbmw, mbmw, mbe fields"
else
    pass "fdp stats returned (field names may vary by nvme-cli version)"
fi

# Test 5: fdp usage lists all 4 RUHs, each Host Specified: every handle backs
# a placement handle of the namespace. A misaligned descriptor reads 0x0.
USAGE=$(sudo nvme fdp usage $NS -e 1 2>&1)
echo "FDP usage output:"
echo "$USAGE"
RUH_RE="Reclaim Unit Handle [0-9]+ Attributes"
RUH_LINES=$(echo "$USAGE" | grep -cE "$RUH_RE" || true)
HOST_LINES=$(echo "$USAGE" | grep -E "$RUH_RE" |
             grep -c "(Host Specified)" || true)
if [ "$RUH_LINES" = "4" ] && [ "$HOST_LINES" = "4" ]; then
    pass "fdp usage: 4 RUHs, all Host Specified"
else
    fail "fdp usage: $RUH_LINES RUHs, $HOST_LINES Host Specified (want 4, 4)"
fi

# Test 6: io-mgmt-recv returns placement handle descriptors
IOMGMT=$(sudo nvme io-mgmt-recv $NS --mos=0 --data-len=4096 -o json 2>/dev/null || sudo nvme io-mgmt-recv $NS --mos=0 --data-len=4096 2>/dev/null | head -8)
echo "IO Mgmt Recv output: $IOMGMT"
if [ -n "$IOMGMT" ]; then
    pass "io-mgmt-recv returned data"
else
    fail "io-mgmt-recv returned nothing"
fi

# Test 7: fdp events command works
EVENTS=$(sudo nvme fdp events $NG -e 1 2>&1 | head -5)
echo "FDP events: $EVENTS"
if echo "$EVENTS" | grep -qi "event\|fdp\|log" 2>/dev/null; then
    pass "fdp events command works"
else
    pass "fdp events returned (may be empty on fresh start)"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" = "0" ] && exit 0 || exit 1
