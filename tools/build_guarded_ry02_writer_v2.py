#!/usr/bin/env python3

from __future__ import annotations

import hashlib
from pathlib import Path


SOURCE = Path("tools/ATC_RF03_Writer_RY02_Guarded.html")
OUTPUT = Path("tools/ATC_RF03_Writer_RY02_Queued.html")

EXPECTED_SOURCE_SHA256 = (
    "6382de1ae23087311b850532b7f8c171f16ffa395d4b45a800c89c7e4aeffcc4"
)

START_MARKER = " let otaAckBusy = false;"
END_MARKER = " function parseACKdata(dataIn) {"


REPLACEMENT = r'''
 let otaAckQueue = Promise.resolve();

 function handleNotifyOTA(dataIn) {

 if (currentOTAstate == 0) {
 return;
 }

 /*
  * BLE notifications may arrive before the async transmission
  * routine that triggered them has returned. Queue ACK processing
  * instead of dropping a valid overlapping notification.
  */
 const queuedFrame = String(dataIn);

 otaAckQueue = otaAckQueue
     .then(function () {
         return processOTAAck(queuedFrame);
     })
     .catch(function (error) {
         addLog("OTA ACK queue exception: " + error);
         console.error(error);
         resetOTAVariables();
     });

 }

 async function processOTAAck(dataIn) {

 if (currentOTAstate == 0) {
 addLog("Ignoring stale OTA ACK after OTA reset");
 return;
 }

 const ack = parseACKdata(dataIn);

 if (!ack.ok) {
 addLog("OTA ACK rejected locally: " + ack.error);
 resetOTAVariables();
 return;
 }

 const inCMD = ack.cmd;
 const status = ack.payload.length > 0
     ? ack.payload[0]
     : 0;

 addLog(
     "OTA ACK cmd=" + inCMD +
     " status=0x" +
     status.toString(16).padStart(2, "0") +
     " state=" + currentOTAstate
 );

 if (status !== 0) {
 addLog(
     "Device rejected OTA command " + inCMD +
     " with status 0x" +
     status.toString(16).padStart(2, "0") +
     "; OTA aborted without activation."
 );
 resetOTAVariables();
 return;
 }

 if (currentOTAstate == 1 && inCMD == 1) {

 /*
  * Change state before transmitting. The device may respond
  * immediately, but its ACK will safely wait in otaAckQueue.
  */
 currentOTAstate = 2;

 sendcmd(bytesToHex(addHeader(
     2,
     hexToBytes(
         "01" +
         intToHex4invers(lenCompleteOTA) +
         intToHex(crc16allOTA) +
         intToHex(checksumallOTA)
     )
 )));

 return;

 }

 if (currentOTAstate == 2 && inCMD == 2) {

 currentOTAstate = 3;

 const sent = await otaBigPart();

 if (!sent) {
 addLog("OTA unexpectedly had no data blocks.");
 resetOTAVariables();
 }

 return;

 }

 if (currentOTAstate == 3 && inCMD == 3) {

 const sent = await otaBigPart();

 if (!sent) {

 currentOTAstate = 4;
 sendcmd(bytesToHex(addHeader(4, null)));

 }

 return;

 }

 if (currentOTAstate == 4 && inCMD == 4) {

 /*
  * Command 5 activates/finalizes the image. Only reach this path
  * after every data part and command 4 returned status 0.
  */
 currentOTAstate = 5;
 sendcmd(bytesToHex(addHeader(5, null)));

 resetOTAVariables();

 addLog(
     "The upload is done; expect a disconnection now."
 );

 return;

 }

 addLog(
     "Unexpected OTA ACK: state=" +
     currentOTAstate +
     " cmd=" +
     inCMD
 );

 resetOTAVariables();

 }

'''


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    if not SOURCE.exists():
        raise SystemExit(f"Source writer not found: {SOURCE}")

    original_bytes = SOURCE.read_bytes()
    original_sha = sha256(original_bytes)

    if original_sha != EXPECTED_SOURCE_SHA256:
        raise SystemExit(
            "Source writer SHA-256 mismatch.\n"
            f"Expected: {EXPECTED_SOURCE_SHA256}\n"
            f"Actual:   {original_sha}"
        )

    original = original_bytes.decode("utf-8")

    start = original.find(START_MARKER)
    if start < 0:
        raise SystemExit("otaAckBusy start marker was not found.")

    end = original.find(END_MARKER, start)
    if end < 0:
        raise SystemExit("parseACKdata end marker was not found.")

    modified = (
        original[:start]
        + REPLACEMENT
        + original[end:]
    )

    required = [
        "let otaAckQueue = Promise.resolve();",
        "function handleNotifyOTA(dataIn)",
        "async function processOTAAck(dataIn)",
        "return processOTAAck(queuedFrame);",
        "currentOTAstate = 3;",
        "const sent = await otaBigPart();",
        "status !== 0",
        "OTA_FRAGMENT_DELAY_MS = 100",
    ]

    for marker in required:
        if marker not in modified:
            raise SystemExit(
                f"Generated writer is missing marker: {marker}"
            )

    forbidden = [
        "let otaAckBusy = false;",
        "Ignoring overlapping OTA ACK",
        "arrayCheck[6 + i]",
        "delay(50);",
    ]

    for marker in forbidden:
        if marker in modified:
            raise SystemExit(
                f"Generated writer still contains forbidden marker: {marker}"
            )

    OUTPUT.write_text(modified, encoding="utf-8")
    output_sha = sha256(OUTPUT.read_bytes())

    print("Queued-ACK RY02 writer created.")
    print()
    print(f"Source: {SOURCE}")
    print(f"Output: {OUTPUT}")
    print()
    print(f"Source SHA-256: {original_sha}")
    print(f"Output SHA-256: {output_sha}")
    print()
    print("ACK handling: serialized promise queue")
    print("Overlapping ACKs: queued, never discarded")
    print("Fragment size: 200 bytes")
    print("Fragment delay: 100 ms")
    print("Nonzero status: abort without activation")


if __name__ == "__main__":
    main()
