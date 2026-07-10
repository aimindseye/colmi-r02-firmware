#!/usr/bin/env python3

from __future__ import annotations

import hashlib
from pathlib import Path


SOURCE = Path.home() / (
    "Documents/projects/atc1441.github.io/"
    "ATC_RF03_Writer.html"
)

OUTPUT = Path("tools/ATC_RF03_Writer_RY02_Guarded.html")


def replace_between(
    text: str,
    start_marker: str,
    end_marker: str,
    replacement: str,
) -> str:
    start = text.find(start_marker)

    if start < 0:
        raise RuntimeError(
            f"Start marker was not found:\n{start_marker}"
        )

    end = text.find(end_marker, start)

    if end < 0:
        raise RuntimeError(
            f"End marker was not found:\n{end_marker}"
        )

    return text[:start] + replacement + text[end:]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    if not SOURCE.exists():
        raise SystemExit(f"Source writer not found: {SOURCE}")

    original = SOURCE.read_text(encoding="utf-8")
    modified = original

    ack_block = r'''
 let otaAckBusy = false;

 async function handleNotifyOTA(dataIn) {

 if (currentOTAstate == 0) {
 return;
 }

 if (otaAckBusy) {
 addLog("Ignoring overlapping OTA ACK");
 return;
 }

 otaAckBusy = true;

 try {

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
     status.toString(16).padStart(2, "0")
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

 sendcmd(bytesToHex(addHeader(
     2,
     hexToBytes(
         "01" +
         intToHex4invers(lenCompleteOTA) +
         intToHex(crc16allOTA) +
         intToHex(checksumallOTA)
     )
 )));

 currentOTAstate = 2;

 } else if (currentOTAstate == 2 && inCMD == 2) {

 if (await otaBigPart()) {
 currentOTAstate = 3;
 } else {
 resetOTAVariables();
 addLog(
     "OTA unexpectedly had no data blocks."
 );
 }

 } else if (currentOTAstate == 3 && inCMD == 3) {

 if (!(await otaBigPart())) {

 currentOTAstate = 4;
 sendcmd(bytesToHex(addHeader(4, null)));

 }

 } else if (currentOTAstate == 4 && inCMD == 4) {

 sendcmd(bytesToHex(addHeader(5, null)));
 resetOTAVariables();

 addLog(
     "The upload is done; expect a disconnection now."
 );

 } else {

 addLog(
     "Unexpected OTA ACK: state=" +
     currentOTAstate +
     " cmd=" +
     inCMD
 );

 resetOTAVariables();

 }

 } catch (error) {

 addLog("OTA handler exception: " + error);
 console.error(error);
 resetOTAVariables();

 } finally {

 otaAckBusy = false;

 }

 }

 function parseACKdata(dataIn) {

 const arrayIn = hexToBytes(dataIn);

 if (arrayIn.length < 6) {
 return {
     ok: false,
     error: "length below six bytes",
 };
 }

 const payloadLength =
     arrayIn[2] |
     (arrayIn[3] << 8);

 if (arrayIn[0] !== 0xbc) {
 return {
     ok: false,
     error: "wrong frame marker",
 };
 }

 if (payloadLength !== arrayIn.length - 6) {
 return {
     ok: false,
     error:
         "declared payload length " +
         payloadLength +
         " does not match actual " +
         (arrayIn.length - 6),
 };
 }

 const payload = arrayIn.slice(6);

 const receivedCRC =
     arrayIn[4] |
     (arrayIn[5] << 8);

 const calculatedCRC =
     payload.length === 0
         ? 0xffff
         : crc16(payload);

 if (receivedCRC !== calculatedCRC) {
 return {
     ok: false,
     error:
         "CRC mismatch received=0x" +
         receivedCRC.toString(16).padStart(4, "0") +
         " calculated=0x" +
         calculatedCRC.toString(16).padStart(4, "0"),
 };
 }

 return {
     ok: true,
     cmd: arrayIn[1],
     payload: payload,
 };

 }

'''

    modified = replace_between(
        modified,
        " function handleNotifyOTA(dataIn) {",
        " function addHeader(type, arrayIn) {",
        ack_block,
    )

    ota_part_block = r'''
 async function otaBigPart() {

 const startOffset = currentOTAposition * 0x400;

 if (startOffset >= firmwareArray.length) {
 addLog("No OTA parts left");
 return false;
 }

 let length = Math.min(
     0x400,
     firmwareArray.length - startOffset
 );

 const payload = new Uint8Array(length + 2);
 const partNumber = currentOTAposition + 1;

 payload[0] = partNumber & 0xff;
 payload[1] = (partNumber >> 8) & 0xff;

 for (let index = 0; index < length; index++) {
 payload[2 + index] =
     firmwareArray[startOffset + index] & 0xff;
 }

 const packet = addHeader(3, payload);
 const totalParts = Math.ceil(
     firmwareArray.length / 0x400
 );

 addLog(
     "Sending OTA Part: " +
     partNumber +
     " from: " +
     totalParts
 );

 updateProgressBar();

 await BLEsendBig(packet);

 currentOTAposition++;

 return true;

 }

'''

    modified = replace_between(
        modified,
        " function otaBigPart() {",
        " function otaStart() {",
        ota_part_block,
    )

    send_block = r'''
 const OTA_FRAGMENT_SIZE = 200;
 const OTA_FRAGMENT_DELAY_MS = 100;

 async function BLEsendBig(arrayIn) {

 let offset = 0;
 let fragmentNumber = 0;

 while (offset < arrayIn.length) {

 const end = Math.min(
     offset + OTA_FRAGMENT_SIZE,
     arrayIn.length
 );

 const fragment = arrayIn.slice(offset, end);

 fragmentNumber++;

 addLog(
     "  fragment " +
     fragmentNumber +
     " bytes=" +
     fragment.length
 );

 await sendCommand(fragment);
 await delay(OTA_FRAGMENT_DELAY_MS);

 offset = end;

 }

 }

'''

    modified = replace_between(
        modified,
        " async function BLEsendBig(arrayIn) {",
        " ////// Other non OTA cmd",
        send_block,
    )

    required_markers = [
        "async function handleNotifyOTA",
        "function parseACKdata",
        "async function otaBigPart",
        "OTA_FRAGMENT_DELAY_MS = 100",
        "await delay(OTA_FRAGMENT_DELAY_MS)",
        "status !== 0",
    ]

    for marker in required_markers:
        if marker not in modified:
            raise RuntimeError(
                f"Generated writer is missing marker: {marker}"
            )

    if modified == original:
        raise RuntimeError("No modifications were made.")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(modified, encoding="utf-8")

    print("Guarded RY02 writer created.")
    print()
    print(f"Source: {SOURCE}")
    print(f"Output: {OUTPUT}")
    print()
    print(
        "Source SHA-256: "
        + sha256(original.encode("utf-8"))
    )
    print(
        "Output SHA-256: "
        + sha256(modified.encode("utf-8"))
    )
    print()
    print(
        "Fragment size:  200 bytes\n"
        "Fragment delay: 100 ms\n"
        "Nonzero status: abort without activation\n"
        "Automatic retry: disabled"
    )


if __name__ == "__main__":
    main()
