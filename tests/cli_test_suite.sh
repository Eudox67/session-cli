#!/bin/bash

# CLI Test Suite for session-cli
# Performs a "Note to Self" round-trip.

BIN="./bin/session-cli"
LOG="tests/cli_test.log"
BASE_CONFIG="tests/test_session.conf"
SEED_FILE="tests/test_seed.bin"

if [ ! -f "$BIN" ]; then
    echo "Error: session-cli not found in bin/. Please run 'make build' first."
    exit 1
fi

rm -f "$LOG" "$BASE_CONFIG" "$SEED_FILE"

echo "=== Session CLI Test Suite ===" | tee -a "$LOG"
echo "Started at: $(date)" | tee -a "$LOG"

run_test() {
    local desc=$1
    shift
    echo -n "[ ] $desc... " | tee -a "$LOG"
    $BIN --config "$BASE_CONFIG" "$@" >> "$LOG" 2>&1
    local ret=$?
    [ $ret -eq 0 ] && echo -e "\r[PASS] $desc" | tee -a "$LOG" || echo -e "\r[FAIL] $desc (Exit $ret)" | tee -a "$LOG"
    return $ret
}

# 1. Init
run_test "Initialize Identity" init --force
MY_ID=$(grep "Session ID:" "$LOG" | tail -n 1 | awk '{print $NF}')
echo "Test Session ID: $MY_ID" | tee -a "$LOG"

# 2. NOTE TO SELF ROUND-TRIP
echo "--- Starting Note to Self Test ---" | tee -a "$LOG"
TEST_DOC="tests/test_note.txt"
echo "Note to self: $(date)" > "$TEST_DOC"
ORIG_MD5=$(md5sum "$TEST_DOC" | awk '{print $1}')

run_test "Send Note to Self" -v send "$MY_ID" "Attachment Check" "$TEST_DOC"

echo "Waiting 20s for propagation..." | tee -a "$LOG"
sleep 20

echo "Polling swarm for Note to Self (up to 60s)..." | tee -a "$LOG"
ATTR_URL=""
ATTR_KEY=""

for i in {1..12}; do
    echo -n "  Attempt $i: " | tee -a "$LOG"
    
    # Simple receive with standard config
    RECV_JSON=$($BIN --config "$BASE_CONFIG" -v receive 2>>"$LOG")
    echo "$RECV_JSON" > "tests/last_receive.json"
    
    ATTR_URL=$(echo "$RECV_JSON" | jq -r '.[] | select(.envelope.dataMessage.attachments != null) | .envelope.dataMessage.attachments[0].url' | head -n 1)
    ATTR_KEY=$(echo "$RECV_JSON" | jq -r '.[] | select(.envelope.dataMessage.attachments != null) | .envelope.dataMessage.attachments[0].key' | head -n 1)

    if [ -n "$ATTR_URL" ] && [ "$ATTR_URL" != "null" ]; then
        echo "Found!" | tee -a "$LOG"
        break
    fi
    echo "Not found yet." | tee -a "$LOG"
    sleep 5
done

if [ -z "$ATTR_URL" ] || [ "$ATTR_URL" == "null" ]; then
    echo "[FAIL] Retrieving metadata (Timed out)" | tee -a "$LOG"
else
    echo "  URL: $ATTR_URL" >> "$LOG"
    DL_DOC="tests/downloaded_note.txt"
    rm -f "$DL_DOC"
    run_test "Download Note" download "$ATTR_URL" "$ATTR_KEY" "$DL_DOC"
    
    if [ -f "$DL_DOC" ]; then
        DL_MD5=$(md5sum "$DL_DOC" | awk '{print $1}')
        if [ "$ORIG_MD5" == "$DL_MD5" ]; then
            echo "[PASS] Integrity Match" | tee -a "$LOG"
        else
            echo "[FAIL] Integrity Mismatch (Orig: $ORIG_MD5, DL: $DL_MD5)" | tee -a "$LOG"
        fi
    else
        echo "[FAIL] Download failed" | tee -a "$LOG"
    fi
fi

echo "=== Test Suite Finished ===" | tee -a "$LOG"
