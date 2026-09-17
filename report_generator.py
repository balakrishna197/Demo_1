# flake8: noqa
# pyright: reportOptionalSubscript=false, reportArgumentType=false, reportCallIssue=false, reportFunctionMemberAccess=false, reportUnusedVariable=false

import os
import re
import csv
import datetime
from collections import defaultdict, OrderedDict
from dataclasses import dataclass
from html import escape
import logging
from drivers.Parse_handler import (
    HEADER_ALIASES,
    find_column,
    load_testcase_sequence,
)
from drivers.did_decoder import decode_special_did_value

DESCRIPTION_MAP = {}
DESCRIPTION_SEQUENCE = []


def parse_expected_bytes(expected_response_data):
    expected_response_data = (expected_response_data or "").replace(",", " ")
    return [
        b.replace("0x", "").upper()
        for b in expected_response_data.split()
        if b
    ]


def build_request_payload_from_step(step):
    if not step or step[0] == "WAIT":
        return []

    (
        _tc_id,
        _description,
        sid,
        sub,
        _expected_response_data,
        write_data,
        _addressing,
        _format_type,
        status_mask,
        communication_type,
        controltype,
    ) = step

    sid_bytes = split_hex_pairs(sid)
    sub_bytes = split_hex_pairs(sub)
    write_bytes = split_hex_pairs(write_data)
    status_mask_bytes = split_hex_pairs(status_mask)
    communication_type_bytes = split_hex_pairs(communication_type)
    controltype_bytes = split_hex_pairs(controltype)

    if not sid_bytes:
        return []

    service = sid_bytes[0]
    payload = list(sid_bytes)
    payload.extend(sub_bytes)

    if service == "19":
        payload.extend(status_mask_bytes)
        payload.extend(write_bytes)
        return payload

    if service == "28":
        payload.extend(communication_type_bytes)
        payload.extend(write_bytes)
        return payload

    if service == "2F":
        payload.extend(controltype_bytes)
        payload.extend(write_bytes)
        return payload

    payload.extend(write_bytes)
    return payload


def build_single_frame(payload):
    payload = list(payload or [])
    if len(payload) <= 15:
        return [f"{len(payload):02X}"] + payload

    total_len = len(payload)
    first_frame_length = f"{0x10 | ((total_len >> 8) & 0x0F):02X}"
    second_frame_length = f"{total_len & 0xFF:02X}"
    return [first_frame_length, second_frame_length] + payload


def payload_to_display_frame(payload):
    return build_single_frame(payload)


def build_request_candidate_keys(request_bytes):
    if not request_bytes:
        return []

    known_sids = {
        "10", "11", "14", "19", "22", "27", "28",
        "2E", "2F", "31", "3E", "85",
    }
    sid_index = -1
    sid = ""

    for idx, byte in enumerate(request_bytes):
        if byte.upper() in known_sids:
            sid_index = idx
            sid = byte.upper()
            break

    if sid_index == -1:
        return []

    candidate_keys = []
    remaining_len = len(request_bytes) - sid_index - 1
    for length in range(remaining_len, -1, -1):
        sub = "".join(
            request_bytes[sid_index + 1:sid_index + 1 + length]
        ).upper()
        candidate_keys.append(
            (sid, sub)
        )
    return candidate_keys


def load_description_map(txt_file_path):
    desc_map = {}
    for step in load_testcase_sequence(txt_file_path):
        if not step or step[0] == "WAIT":
            continue

        (
            tc_id,
            description,
            sid,
            sub,
            expected_response_data,
            write_data,
            _addressing,
            format_type,
            status_mask,
            communication_type,
            controltype,
        ) = step

        sid = sid.strip().replace("0x", "").upper()
        sub = sub.strip().replace("0x", "").upper()
        expected_bytes = parse_expected_bytes(expected_response_data)
        key = (sid, sub)
        value = (
            description.strip(),
            tc_id.strip(),
            expected_bytes,
            (format_type or "Hex").strip().capitalize(),
            build_request_payload_from_step(
                (
                    tc_id,
                    description,
                    sid,
                    sub,
                    expected_response_data,
                    write_data,
                    _addressing,
                    format_type,
                    status_mask,
                    communication_type,
                    controltype,
                )
            )
        )
        if key not in desc_map:
            desc_map[key] = []
        desc_map[key].append(value)
    return desc_map


def build_request_signature_sequence(txt_file_path):
    sequence = []
    for step in load_testcase_sequence(txt_file_path):
        if not step or step[0] == "WAIT":
            continue

        (
            tc_id,
            description,
            sid,
            sub,
            expected_response_data,
            _write_data,
            _addressing,
            format_type,
            *_rest,
        ) = step

        sid_clean = sid.strip().replace("0x", "").upper()
        sub_clean = sub.strip().replace("0x", "").upper()
        expected_bytes = parse_expected_bytes(expected_response_data)
        request_payload = build_request_payload_from_step(step)

        sequence.append(
            {
                "key": (sid_clean, sub_clean),
                "request_payload": request_payload,
                "desc": description.strip(),
                "tc_id": tc_id.strip(),
                "expected_resp": expected_bytes,
                "format": (format_type or "Hex").strip().capitalize(),
            }
        )

    return sequence


def get_testcase_order(txt_file_path):
    ordered_ids = []
    occurrence_counts = defaultdict(int)

    for step in load_testcase_sequence(txt_file_path):
        if not step or step[0] == "WAIT":
            continue

        tc_id = step[0].strip()
        occurrence_counts[tc_id] += 1
        ordered_ids.append(build_occurrence_key(tc_id, occurrence_counts[tc_id]))

    return ordered_ids


def split_hex_pairs(hex_text):
    clean = (hex_text or "").strip()
    clean = clean.replace("0x", "").replace("0X", "")
    clean = clean.replace(",", " ").replace(" ", "").upper()
    if not clean or clean == "-":
        return []
    if len(clean) % 2 != 0:
        return []
    if not re.fullmatch(r"[0-9A-F]+", clean):
        return []
    return [clean[i:i + 2] for i in range(0, len(clean), 2)]


def parse_data_bytes(line, ctype):
    try:
        parts = line.strip().split()

        if ctype == "CANFD":
            candidate_start = None
            candidate_len = 0

            for idx in range(len(parts) - 2):
                if not parts[idx].isdigit() or not parts[idx + 1].isdigit():
                    continue

                possible_len = int(parts[idx + 1])
                if possible_len <= 0 or possible_len > 64:
                    continue

                next_tokens = parts[idx + 2: idx + 2 + possible_len]
                if len(next_tokens) != possible_len:
                    continue

                if all(
                    re.fullmatch(r"[0-9A-Fa-f]{2}", token)
                    for token in next_tokens
                ):
                    candidate_start = idx + 2
                    candidate_len = possible_len
                    break

            if candidate_start is not None:
                return [
                    value.upper()
                    for value in parts[
                        candidate_start: candidate_start + candidate_len
                    ]
                ]

        for idx, token in enumerate(parts):
            if token == "d" and idx + 1 < len(parts):
                try:
                    dlc = int(parts[idx + 1])
                except ValueError:
                    continue

                payload = []
                for value in parts[idx + 2:]:
                    if re.fullmatch(r"[0-9A-Fa-f]{2}", value):
                        payload.append(value.upper())
                    elif payload:
                        break

                if payload:
                    return payload[:dlc]

        match = re.search(
            r"((?:\b[0-9A-Fa-f]{2}\b(?:\s+|$))+)$", line.strip()
        )
        if match:
            return [byte.upper() for byte in match.group(1).split()]
    except Exception:
        pass
    return []


def get_request_match_bytes(data_bytes):
    data = [b.strip().upper() for b in data_bytes if isinstance(b, str)]
    if not data:
        return []

    try:
        pci = int(data[0], 16)
    except ValueError:
        return data

    frame_type = (pci >> 4) & 0x0F

    if frame_type == 0:
        declared_payload_len = pci & 0x0F
        declared_end = min(len(data), 1 + declared_payload_len)
        declared_payload = data[1:declared_end]
        extra_bytes = list(data[declared_end:])

        while extra_bytes and extra_bytes[-1] in ("00", "AA"):
            extra_bytes.pop()

        if extra_bytes:
            return declared_payload + extra_bytes
        return declared_payload

    if frame_type == 1 and len(data) >= 2:
        payload_len = ((pci & 0x0F) << 8) | int(data[1], 16)
        return data[2:2 + payload_len]

    return data


def get_description(data_bytes):
    if not data_bytes or len(data_bytes) < 1:
        return "", "", "", ""

    request_bytes = get_request_match_bytes(data_bytes)
    if not request_bytes:
        return "", "", "", ""

    candidate_keys = build_request_candidate_keys(request_bytes)
    if not candidate_keys:
        return "", "", "", ""

    sequence = getattr(get_description, "sequence", [])
    cursor = getattr(get_description, "sequence_cursor", 0)
    used_indices = getattr(get_description, "sequence_used_indices", set())

    for idx in range(cursor, len(sequence)):
        entry = sequence[idx]
        if idx in used_indices:
            continue
        if entry.get("request_payload") == request_bytes or (
            not entry.get("request_payload") and entry["key"] in candidate_keys
        ):
            used_indices.add(idx)
            setattr(get_description, "sequence_used_indices", used_indices)
            setattr(get_description, "sequence_cursor", idx + 1)
            return (
                entry["desc"],
                entry["tc_id"],
                entry["expected_resp"],
                entry["format"],
            )

    for idx, entry in enumerate(sequence):
        if idx in used_indices:
            continue
        if entry.get("request_payload") == request_bytes or (
            not entry.get("request_payload") and entry["key"] in candidate_keys
        ):
            used_indices.add(idx)
            setattr(get_description, "sequence_used_indices", used_indices)
            setattr(get_description, "sequence_cursor", max(cursor, idx + 1))
            return (
                entry["desc"],
                entry["tc_id"],
                entry["expected_resp"],
                entry["format"],
            )

    if not sequence:
        for key in candidate_keys:
            if key in DESCRIPTION_MAP:
                desc, tc_id, expected_resp, fmt, _request_payload = DESCRIPTION_MAP[key][0]
                return desc, tc_id, expected_resp, fmt

    return "", "", "", ""


def get_failure_reason(nrc):
    reasons = {
        "10": "generalReject",
        "11": "serviceNotSupported",
        "12": "subFunctionNotSupported",
        "13": "incorrectMessageLengthOrInvalidFormat",
        "14": "responseTooLong",
        "21": "busyRepeatReques",
        "22": "conditionsNotCorrect",
        "23": "ISOSAEReserved",
        "24": "requestSequenceError",
        "31": "requestOutOfRange",
        "32": "ISOSAEReserved",
        "33": "securityAccessDenied",
        "34": "ISOSAEReserved",
        "35": "invalidKey",
        "36": "exceedNumberOfAttempts",
        "37": "requiredTimeDelayNotExpired",
        "70": "uploadDownloadNotAccepted",
        "71": "transferDataSuspended",
        "72": "generalProgrammingFailure",
        "73": "wrongBlockSequenceCounter",
        "78": "requestCorrectlyReceived-ResponsePending",
        "7E": "subFunctionNotSupportedInActiveSession",
        "7F": "serviceNotSupportedInActiveSession",
        "80": "ISOSAEReserved",
        "81": "rpmTooHigh",
        "82": "rpmTooLow",
        "83": "engineIsRunning",
        "84": "engineIsNotRunning",
        "85": "engineRunTimeTooLow",
        "86": "temperatureTooHigh",
        "87": "temperatureTooLow",
        "88": "vehicleSpeedTooHigh",
        "89": "vehicleSpeedTooLow",
        "8A": "throttle/PedalTooHigh",
        "8B": "throttle/PedalTooLow",
        "8C": "transmissionRangeNotInNeutral",
        "8D": "transmissionRangeNotInGear",
        "8E": "ISOSAEReserved",
        "8F": (
            "brakeSwitch(es)NotClosed (Brake Pedal not pressed or not applied)"
        ),
        "90": "shifterLeverNotInPark",
        "91": "torqueConverterClutchLocked",
        "92": "voltageTooHigh",
        "93": "voltageTooLow",
        "FF": "ISOSAEReserved",
    }
    return reasons.get(nrc.upper(), f"Unknown NRC: {nrc}")


def normalize_hex_bytes(data_bytes):
    return [b.strip().upper() for b in data_bytes if isinstance(b, str)]


def extract_isotp_payload(data_bytes):
    data = normalize_hex_bytes(data_bytes)
    if not data:
        return []

    try:
        pci = int(data[0], 16)
    except ValueError:
        return data

    frame_type = (pci >> 4) & 0x0F

    if frame_type == 0:
        payload_len = pci & 0x0F
        return data[1:1 + payload_len]

    if frame_type == 1 and len(data) >= 2:
        payload_len = ((pci & 0x0F) << 8) | int(data[1], 16)
        return data[2:2 + payload_len]

    return data


def normalize_response_payload(data_bytes):
    data = normalize_hex_bytes(data_bytes)
    if not data:
        return []

    try:
        pci = int(data[0], 16)
    except ValueError:
        return data

    frame_type = (pci >> 4) & 0x0F
    if frame_type in (0x0, 0x1):
        return extract_isotp_payload(data)
    return data


def normalize_for_compare(data_bytes):
    raw = remove_trailing_padding(
        remove_trailing_padding(normalize_hex_bytes(data_bytes), "00"),
        "AA",
    )
    payload = remove_trailing_padding(
        remove_trailing_padding(extract_isotp_payload(raw), "00"),
        "AA",
    )
    return raw, payload


def trim_compare_padding(data_bytes):
    trimmed = list(data_bytes or [])
    while trimmed and trimmed[-1] in ("00", "AA", "20"):
        trimmed.pop()
    return trimmed


def response_compare_variants(data_bytes):
    raw = normalize_hex_bytes(data_bytes)
    payload = normalize_response_payload(raw)
    variants = []

    for candidate in (raw, payload):
        if candidate and candidate not in variants:
            variants.append(candidate)

        trimmed = trim_compare_padding(candidate)
        if trimmed and trimmed not in variants:
            variants.append(trimmed)
            
    return variants


def expected_declared_payload(expected_response_data):
    expected = trim_compare_padding(normalize_hex_bytes(expected_response_data))
    if not expected:
        return []

    try:
        pci = int(expected[0], 16)
    except ValueError:
        return []

    frame_type = (pci >> 4) & 0x0F
    if frame_type == 0x0:
        declared_len = pci & 0x0F
        return expected[1:1 + declared_len]

    if frame_type == 0x1 and len(expected) >= 2:
        declared_len = ((pci & 0x0F) << 8) | int(expected[1], 16)
        return expected[2:2 + declared_len]

    return []


def trim_optional_trailing_spaces(data_bytes):
    trimmed = list(data_bytes)
    while trimmed and trimmed[-1] == "20":
        trimmed.pop()
    return trimmed


def is_empty_positive_read_response(data_bytes):
    payload = normalize_response_payload(data_bytes)
    if len(payload) < 3 or payload[0] != "62":
        return False

    did = "".join(payload[1:3]).upper()
    if did == "F18B":
        return False

    did_data = remove_trailing_padding(
        remove_trailing_padding(payload[3:], "00"),
        "AA",
    )
    return len(did_data) == 0


def get_status(actual_data, expected_response_data):
    """
    Determines Pass/Fail by comparing full actual vs expected response.
    Handles negative responses with NRCs too.
    """
    if not actual_data:
        return "Fail", "No response received"
    if not expected_response_data:
        return "Fail", "Expected response not specified"

    actual_variants = response_compare_variants(actual_data)
    expected_variants = response_compare_variants(expected_response_data)

    if any(actual == expected for actual in actual_variants for expected in expected_variants):
        return "Pass", ""

    # 🟥 Negative Response Handling
    _actual_raw, actual_payload = normalize_for_compare(actual_data)
    if len(actual_payload) >= 3 and actual_payload[0] == "7F":
        nrc = actual_payload[2]
        return 
            "Fail",
            f"Negative Response (0x{nrc}: {get_failure_reason(nrc)})"

    if is_empty_positive_read_response(actual_data):
        return "Fail", "Empty response data"

    return "Fail", "Response mismatch"


def parse_line(line):
    line = line.strip()
    if not line:
        return None

    timestamp_match = re.match(r"^(?P<timestamp>\d+\.\d+)", line)
    if not timestamp_match:
        return None

    parts = line.split()
    timestamp = float(timestamp_match.group("timestamp"))

    if "errorframe" in line.lower():
        direction = "Tx" if "Tx" in parts else "Rx" if "Rx" in parts else ""
        return {
            "timestamp": timestamp,
            "can_id": "ERROR",
            "direction": direction,
            "data_bytes": [],
            "raw": line,
            "frame_kind": "error",
        }

    if "CANFD" not in line and " d " not in line:
        return None

    try:
        direction_idx = next(
            idx for idx, token in enumerate(parts) if token in ("Tx", "Rx")
        )
    except StopIteration:
        return None

    direction = parts[direction_idx]
    ctype = "CANFD" if "CANFD" in line else "CAN"
    can_id = None

    for idx in (direction_idx - 1, direction_idx + 1, direction_idx - 2, direction_idx + 2):
        if 0 <= idx < len(parts) and re.fullmatch(r"[0-9A-Fa-f]{3,8}", parts[idx]):
            can_id = parts[idx].upper()
            break

    if can_id is None:
        return None

    return {
        "timestamp": timestamp,
        "can_id": can_id,
        "direction": direction,
        "data_bytes": parse_data_bytes(line, ctype),
        "raw": line,
        "frame_kind": "message",
    }


def parse_asc_file(asc_file_path, allowed_tx_ids, allowed_rx_ids):
    messages_by_tc = defaultdict(list)
    current_request = None
    pending_first_frame = None
    assembling_request = False
    request_buffer = []
    total_req_len = 0

    awaiting_response = False
    response_buffer = []
    total_resp_len = 0
    collected_len = 0
    skip_next_fc = False
    pending_flag = False
    pending_error_frame = None

    start_ts, end_ts = None, None

    def finalize_request(failure_reason, response=None, response_data_bytes=None, response_type=None):
        nonlocal current_request, start_ts, end_ts
        if not current_request:
            return

        current_request.update({
            "response": response or {},
            "response_data_bytes": response_data_bytes or [],
            "status": "Fail",
            "failure_reason": failure_reason,
            "response_type": response_type or "Response Received",
        })
        messages_by_tc[current_request["tc_id"]].append(current_request)
        start_ts = min(start_ts or current_request["timestamp"], current_request["timestamp"])
        response_ts = (
            response.get("timestamp")
            if response and isinstance(response.get("timestamp"), (int, float))
            else current_request["timestamp"]
        )
        end_ts = max(end_ts or response_ts, response_ts)
        current_request = None


    allowed_tx_ids = set(f"{id:X}" for id in allowed_tx_ids)
    allowed_rx_ids = set(f"{id:X}" for id in allowed_rx_ids)
    
    ALLOWED_IDS = allowed_tx_ids | allowed_rx_ids
    
    with open(asc_file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if not line or not re.match(r"^\d+\.\d+", line):
            continue

        msg = parse_line(line)
        if not msg:
            continue

        if msg["frame_kind"] == "error":
            if current_request:
                pending_error_frame = msg
            continue

        if msg["can_id"] not in ALLOWED_IDS:
            continue

        can_id = msg["can_id"]
        direction = msg["direction"]
        data = msg["data_bytes"]

        if not data:
            if direction == "Rx" and current_request:
                finalize_request(
                    "Received frame without payload",
                    response=msg,
                    response_data_bytes=[],
                    response_type="Empty Frame",
                )
                awaiting_response = False
                response_buffer = []
                pending_flag = False
                pending_error_frame = None
            continue
        
        # 🟦 Tx: Handle Request
        if direction == "Tx" and can_id in allowed_tx_ids:
            pci_type = data[0].upper()

            # Tester flow-control frames belong to the active ISO-TP response
            # transfer and must not be treated as a new diagnostic request.
            if current_request and awaiting_response and pci_type == "30":
                continue

            if current_request:
                failure_reason = (
                    "Incomplete multi-frame response"
                    if awaiting_response or response_buffer
                    else "No response received"
                )
                response = None
                response_type = "No Response"
                if pending_error_frame:
                    failure_reason = "CAN error frame detected before response"
                    response = pending_error_frame
                    response_type = "Error Frame"
                finalize_request(
                    failure_reason,
                    response=response,
                    response_data_bytes=response_buffer[:],
                    response_type=response_type,
                )
                awaiting_response = False
                response_buffer = []
                pending_flag = False
                pending_error_frame = None

            if pci_type == "10":  # First Frame of Multi-Frame Request
                assembling_request = True
                total_req_len = ((int(data[0], 16) & 0x0F) << 8) | int(data[1], 16)
                request_buffer = data[2:]
                pending_first_frame = msg
                skip_next_fc = True
                continue

            elif skip_next_fc and pci_type == "30":
                skip_next_fc = False
                continue

            elif assembling_request and pci_type.startswith("2"):  # Consecutive Frame
                request_buffer += data[1:]
                if len(request_buffer) >= total_req_len:
                    trimmed_data = request_buffer[:total_req_len]
                    desc, tc_id, expected_resp, fmt = get_description(trimmed_data)
                    if desc and tc_id:
                        current_request = {
                            "timestamp": pending_first_frame["timestamp"],
                            "can_id": pending_first_frame["can_id"],
                            "direction": "Tx",
                            "data_bytes": trimmed_data,
                            "desc": desc,
                            "tc_id": tc_id,
                            "format": fmt,
                            "expected_resp": expected_resp,
                            "status": "Pending"
                        }
                    assembling_request = False
                    request_buffer = []
                    pending_first_frame = None
                continue

            else:  # Single-Frame Request
                desc, tc_id, expected_resp, fmt = get_description(data)
                if desc and tc_id:
                    current_request = {
                        "timestamp": msg["timestamp"],
                        "can_id": can_id,
                        "direction": direction,
                        "data_bytes": data,
                        "desc": desc,
                        "tc_id": tc_id,
                        "format": fmt,
                        "expected_resp": expected_resp,
                        "status": "Pending"
                    }

        # ◀️ Rx: Handle Response
        elif direction == "Rx" and can_id in allowed_rx_ids and current_request:
            pci_type = data[0].upper()

            if pci_type == "30":
                continue  # Ignore flow control

            # Handle 0x7F xx 78 pending response
            if len(data) >= 4 and data[1].upper() == "7F" and data[3].upper() == "78":
                pending_flag = True
                continue  # Ignore pending response

            if pending_flag:
                pending_flag = False
                full_resp = data  # Treat next frame as actual response
            else:
                if pci_type == "10":  # First frame of multi-frame response
                    total_resp_len = ((int(data[0], 16) & 0x0F) << 8) | int(data[1], 16)
                    response_buffer = data[2:]  # payload only
                    collected_len = len(response_buffer)
                    awaiting_response = True
                    continue

                elif pci_type.startswith("2") and awaiting_response:
                    response_buffer += data[1:]  # payload only
                    collected_len += len(data) - 1
                    if collected_len >= total_resp_len:
                        full_resp = response_buffer[:total_resp_len]
                        awaiting_response = False
                    else:
                        continue
                elif pci_type.startswith("2") and not awaiting_response:
                    # Orphan consecutive frame from a previously interrupted
                    # multi-frame transfer. Do not mis-attach it to the next
                    # testcase request.
                    logging.warning(
                        f"Ignoring orphan consecutive frame for active request {current_request['tc_id']}: {msg['raw']}"
                    )
                    continue
                else:
                    if awaiting_response:
                        response_buffer += data[1:]
                        full_resp = response_buffer[:total_resp_len]
                        awaiting_response = False
                    else:
                        full_resp = data

            # ✅ Evaluate response
            status, reason = get_status(full_resp, current_request["expected_resp"])
            current_request.update({
                "response": msg,
                "response_data_bytes": full_resp,
                "status": status,
                "failure_reason": reason,
                "response_type": "Response Received",
            })

            messages_by_tc[current_request["tc_id"]].append(current_request)

            # Update timestamps
            start_ts = min(start_ts or msg["timestamp"], current_request["timestamp"])
            end_ts = max(end_ts or msg["timestamp"], msg["timestamp"])

            current_request = None
            response_buffer = []
            pending_error_frame = None

    if current_request:
        failure_reason = (
            "Incomplete multi-frame response"
            if awaiting_response or response_buffer
            else "No response received"
        )
        response = None
        response_type = "No Response"
        if pending_error_frame:
            failure_reason = "CAN error frame detected before response"
            response = pending_error_frame
            response_type = "Error Frame"
        finalize_request(
            failure_reason,
            response=response,
            response_data_bytes=response_buffer[:],
            response_type=response_type,
        )

    return messages_by_tc, start_ts or 0, end_ts or 0


def build_placeholder_request_bytes(step):
    if not step or step[0] == "WAIT":
        return []
    payload = build_request_payload_from_step(step)

    if not payload:
        return []

    if len(payload) <= 15:
        return [f"{len(payload):02X}"] + payload

    total_len = len(payload)
    return [f"{0x10 | ((total_len >> 8) & 0x0F):02X}", f"{total_len & 0xFF:02X}"] + payload


def build_occurrence_key(tc_id, occurrence_index):
    return f"{tc_id}__occurrence_{occurrence_index}"


def build_placeholder_message(tc_id, occurrence_key, step):
    (
        _tc_id,
        description,
        _sid,
        _sub,
        expected_response_data,
        _write_data,
        _addressing,
        format_type,
        *_rest,
    ) = step

    expected_bytes = [
        b.replace("0x", "").upper()
        for b in (expected_response_data or "").split()
        if b
    ]

    return {
        "timestamp": 0.0,
        "can_id": "",
        "direction": "Tx",
        "data_bytes": build_placeholder_request_bytes(step),
        "desc": description.strip(),
        "tc_id": tc_id,
        "occurrence_key": occurrence_key,
        "format": (format_type or "Hex").strip().capitalize(),
        "expected_resp": expected_bytes,
        "status": "Fail",
        "failure_reason": "Testcase not observed in ASC log",
        "response": {},
        "response_data_bytes": [],
        "response_type": "Not Observed in ASC",
    }


def build_placeholder_messages(txt_file_path):
    placeholders = OrderedDict()
    occurrence_counts = defaultdict(int)

    for step in load_testcase_sequence(txt_file_path):
        if not step or step[0] == "WAIT":
            continue

        tc_id = step[0].strip()
        occurrence_counts[tc_id] += 1
        occurrence_key = build_occurrence_key(tc_id, occurrence_counts[tc_id])
        placeholders[occurrence_key] = [build_placeholder_message(tc_id, occurrence_key, step)]

    return placeholders


def ensure_all_testcases_present(messages_by_tc, txt_file_path):
    occurrence_counts = defaultdict(int)

    for step in load_testcase_sequence(txt_file_path):
        if not step or step[0] == "WAIT":
            continue

        tc_id = step[0].strip()
        occurrence_counts[tc_id] += 1
        occurrence_key = build_occurrence_key(tc_id, occurrence_counts[tc_id])

        if occurrence_key in messages_by_tc:
            continue

        messages_by_tc[occurrence_key].append(
            build_placeholder_message(tc_id, occurrence_key, step)
        )

    return messages_by_tc


def scan_actual_did_responses(asc_file_path, allowed_tx_ids, allowed_rx_ids):
    allowed_tx_ids = set(f"{id:X}" for id in allowed_tx_ids)
    allowed_rx_ids = set(f"{id:X}" for id in allowed_rx_ids)

    did_to_response = {}
    active_request = None
    assembling_request = False
    request_buffer = []
    total_req_len = 0
    awaiting_response = False
    response_buffer = []
    total_resp_len = 0
    collected_len = 0
    pending_flag = False

    def find_did_from_request(data_bytes):
        request_bytes = get_request_match_bytes(data_bytes)
        for idx, byte in enumerate(request_bytes):
            if byte == "22" and idx + 2 < len(request_bytes):
                return "".join(request_bytes[idx + 1: idx + 3]).upper()
        return None

    def finalize_response(full_resp):
        nonlocal active_request, awaiting_response, response_buffer, total_resp_len, collected_len, pending_flag
        if not active_request or not full_resp:
            active_request = None
            awaiting_response = False
            response_buffer = []
            total_resp_len = 0
            collected_len = 0
            pending_flag = False
            return

        payload = extract_isotp_payload(full_resp)
        if len(payload) >= 3 and payload[0] == "62":
            did = "".join(payload[1:3]).upper()
            did_to_response[did] = full_resp
        elif active_request.get("did") and len(payload) >= 2:
            expected_did_bytes = split_hex_pairs(active_request["did"])
            if payload[:2] == expected_did_bytes:
                did_to_response[active_request["did"]] = ["62"] + payload

        active_request = None
        awaiting_response = False
        response_buffer = []
        total_resp_len = 0
        collected_len = 0
        pending_flag = False

    with open(asc_file_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or not re.match(r"^\d+\.\d+", line):
                continue

            msg = parse_line(line)
            if not msg or msg["frame_kind"] != "message":
                continue

            can_id = msg["can_id"]
            direction = msg["direction"]
            data = msg["data_bytes"]

            if not data:
                continue

            pci_type = data[0].upper()

            if direction == "Tx" and can_id in allowed_tx_ids:
                if pci_type == "30" and awaiting_response:
                    continue

                if pci_type == "10":
                    assembling_request = True
                    total_req_len = ((int(data[0], 16) & 0x0F) << 8) | int(data[1], 16)
                    request_buffer = data[2:]
                    continue

                if assembling_request and pci_type.startswith("2"):
                    request_buffer += data[1:]
                    if len(request_buffer) >= total_req_len:
                        trimmed_request = request_buffer[:total_req_len]
                        did = find_did_from_request(trimmed_request)
                        active_request = {"did": did} if did else None
                        assembling_request = False
                        request_buffer = []
                    continue

                if assembling_request:
                    assembling_request = False
                    request_buffer = []

                did = find_did_from_request(data)
                active_request = {"did": did} if did else None
                continue

            if direction == "Rx" and can_id in allowed_rx_ids and active_request:
                if pci_type == "30":
                    continue

                if len(data) >= 4 and data[1].upper() == "7F" and data[3].upper() == "78":
                    pending_flag = True
                    continue

                if pending_flag:
                    pending_flag = False
                    finalize_response(data)
                    continue

                if pci_type == "10":
                    total_resp_len = ((int(data[0], 16) & 0x0F) << 8) | int(data[1], 16)
                    response_buffer = data[2:]
                    collected_len = len(response_buffer)
                    awaiting_response = True
                    continue

                if pci_type.startswith("2") and awaiting_response:
                    response_buffer += data[1:]
                    collected_len += len(data) - 1
                    if collected_len >= total_resp_len:
                        finalize_response(response_buffer[:total_resp_len])
                    continue

                finalize_response(data)

    return did_to_response

# stage.............

def flatten_bytes(data):
    flat = []
    for item in data:
        if isinstance(item, list):
            
            flat.extend(item)
        else:
            flat.append(item)
    return flat

def remove_trailing_padding(data_list, pad_byte):
    # Remove only trailing occurrences of pad_byte (like "00" or "AA")
    i = len(data_list)
    while i > 0 and data_list[i - 1].upper() == pad_byte.upper():
        i -= 1
    return data_list[:i]

def get_valid_request_data(data_bytes):
    """
    Extracts the actual data from a UDS request.
    Assumes the first byte is the PCI, which tells us how many bytes follow.
    """
    
    if not data_bytes:
        return data_bytes
    try:
        pci = int(data_bytes[0], 16)
        if pci <= 0x07:
            # Single-frame: first byte is length of remaining data
            total_len = pci + 1  # include PCI itself
            return data_bytes[:total_len]
    except:
        pass
    return data_bytes


def get_expected_ecu_info_fields(txt_file_path):
    fields = []
    seen = set()
    try:
        with open(txt_file_path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.reader(f)
            header = None
            for row in reader:
                if not row:
                    continue
                first_col = row[0].strip()
                if first_col.startswith("#Author") or first_col.startswith("#Date"):
                    continue
                if first_col.startswith("#TC_ID") or first_col.startswith("TC_ID"):
                    header = [h.strip().lstrip("#") for h in row]
                    break

            if header is None:
                return fields

            col = {name: idx for idx, name in enumerate(header)}
            tc_id_idx = find_column(col, HEADER_ALIASES["TC_ID"])
            desc_idx = find_column(col, HEADER_ALIASES["DESCRIPTION"])

            for row in reader:
                if not row or len(row) <= max(tc_id_idx, desc_idx):
                    continue
                tc_id = row[tc_id_idx].strip()
                desc = row[desc_idx].strip()
                if tc_id.startswith("ECU_INFO") and desc and desc not in seen:
                    seen.add(desc)
                    fields.append(desc)
    except Exception as exc:
        logging.warning(f"Failed to derive ECU info field list from testcase file: {exc}")

    return fields


def normalize_did_string(value):
    if value is None:
        return ""

    text = str(value).strip().upper()
    if not text:
        return ""

    text = text.replace("0X", "")
    text = re.sub(r"\s+", "", text)

    if not text or not re.fullmatch(r"[0-9A-F]+", text):
        return ""

    return text


def looks_like_did(value):
    normalized = normalize_did_string(value)
    return bool(normalized) and len(normalized) <= 8


def build_ecu_info_label_map(ecu_info_field_map):
    did_to_label = OrderedDict()
    ordered_labels = []

    if not isinstance(ecu_info_field_map, dict):
        return did_to_label, ordered_labels

    for raw_key, raw_value in ecu_info_field_map.items():
        key_text = str(raw_key).strip()
        value_text = str(raw_value).strip()

        key_is_did = looks_like_did(key_text)
        value_is_did = looks_like_did(value_text)

        did = ""
        label = ""

        if key_is_did and not value_is_did:
            did = normalize_did_string(key_text)
            label = value_text
        elif value_is_did and not key_is_did:
            did = normalize_did_string(value_text)
            label = key_text
        else:
            continue

        if not did or not label:
            continue

        did_to_label[did] = label
        if label not in ordered_labels:
            ordered_labels.append(label)

    return did_to_label, ordered_labels


def normalize_ecu_info_field_name(value):
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return re.sub(r"[^a-z0-9]+", "", text)


def is_meaningful_ecu_info_value(value):
    if value is None:
        return False
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return False
        if stripped == "ECU No response":
            return False
    return True


def merge_ecu_info_values(primary_values, fallback_values, preferred_order=None):
    merged = {}
    alias_to_canonical = OrderedDict()

    for field in preferred_order or []:
        alias = normalize_ecu_info_field_name(field)
        if alias and alias not in alias_to_canonical:
            alias_to_canonical[alias] = field
        merged[field] = None

    for source in (fallback_values or {}, primary_values or {}):
        for field, value in (source or {}).items():
            alias = normalize_ecu_info_field_name(field)
            canonical = alias_to_canonical.get(alias, field)
            if alias and alias not in alias_to_canonical:
                alias_to_canonical[alias] = canonical
            existing = merged.get(canonical)
            if is_meaningful_ecu_info_value(value):
                merged[canonical] = value
            elif canonical not in merged:
                merged[canonical] = value

    return merged


def extract_request_did(data_bytes):
    payload = extract_isotp_payload(normalize_hex_bytes(data_bytes))
    if len(payload) >= 3 and payload[0].upper() == "22":
        return f"{payload[1]}{payload[2]}".upper()
    return ""


def get_testcase_author(txt_file_path):
    try:
        with open(txt_file_path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                first_col = row[0].strip()
                if first_col.startswith("#Author"):
                    if len(row) > 1 and row[1].strip():
                        return row[1].strip()
                    if ":" in first_col:
                        return first_col.split(":", 1)[1].strip()
                    return "N/A"
                if first_col.startswith("#TC_ID") or first_col.startswith("TC_ID"):
                    break
    except Exception as exc:
        logging.warning(f"Failed to read testcase author from header: {exc}")

    return "N/A"


def get_testcase_generated_metadata(txt_file_path):
    metadata = {
        "filename": os.path.basename(txt_file_path),
        "generated_at": None,
    }

    try:
        with open(txt_file_path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue

                first_col = row[0].strip()
                second_col = row[1].strip() if len(row) > 1 else ""

                if first_col.startswith("#TC_ID") or first_col.startswith("TC_ID"):
                    break

                normalized_key = first_col.lstrip("#").strip().lower()
                if first_col.startswith("#Date") or normalized_key in {"date", "generated", "generated on"}:
                    date_value = ""
                    time_value = ""

                    if ":" in first_col:
                        date_value = first_col.split(":", 1)[1].strip()
                    if second_col:
                        second_col_clean = second_col.strip()
                        if second_col_clean.lower().startswith("time"):
                            time_value = second_col_clean.split(":", 1)[1].strip()
                        else:
                            time_value = second_col_clean

                    combined = f"{date_value} {time_value}".strip()
                    metadata["generated_at"] = combined or metadata["generated_at"]
                elif normalized_key in {"file", "filename", "input file"} and second_col:
                    metadata["filename"] = os.path.basename(second_col)
    except Exception as exc:
        logging.warning(f"Failed to read testcase generated metadata from header: {exc}")

    return metadata


def format_generated_entry(filename, generated_at):
    if not filename or str(filename).upper() == "N/A":
        return "N/A"
    safe_filename = os.path.basename(filename) if filename else "N/A"
    safe_generated_at = generated_at or "N/A"
    if str(safe_generated_at).upper() == "N/A":
        return safe_filename
    safe_generated_at = normalize_generated_time_display(safe_generated_at)
    return f"{safe_filename} ({safe_generated_at})"


def normalize_generated_time_display(generated_at):
    if not generated_at:
        return "N/A"

    raw_value = str(generated_at).strip()
    if not raw_value or raw_value.upper() == "N/A":
        return "N/A"

    cleaned_value = re.sub(
        r"\s+Time\s*:\s*",
        " ",
        re.sub(r"\bDate\s*:\s*", "", raw_value, flags=re.IGNORECASE),
        flags=re.IGNORECASE,
    ).strip()

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y %H:%M",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
    ):
        try:
            parsed = datetime.datetime.strptime(cleaned_value, fmt)
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

    return cleaned_value


def extract_generated_time_from_filename(file_path):
    filename = os.path.basename(file_path or "")
    match = re.search(r"_(\d{8})_(\d{6})(?=\.[^.]+$)", filename)

    if not match:
        return "N/A"

    try:
        timestamp_str = f"{match.group(1)}_{match.group(2)}"
        return datetime.datetime.strptime(
            timestamp_str, "%Y%m%d_%H%M%S"
        ).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        logging.warning(
            f"Failed to extract generated time from filename {filename}: {exc}"
        )
        return "N/A"


def get_file_generated_time(file_path):
    try:
        timestamp = os.path.getmtime(file_path)
        return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except Exception as exc:
        logging.warning(f"Failed to read file timestamp for {file_path}: {exc}")
        return "N/A"

# stage.............
def get_json_generated_time(file_path):
    try:
        filename = os.path.basename(file_path)

        # Extract YYMMDDHHMM from the end of the filename.
        match = re.search(r"_(\d{10})\.json$", filename, re.IGNORECASE)

        if match:
            timestamp_str = match.group(1)
            parsed_time = datetime.datetime.strptime(timestamp_str, "%y%m%d%H%M")
            file_generated_time = get_file_generated_time(file_path)
            if file_generated_time != "N/A":
                try:
                    parsed_file_time = datetime.datetime.strptime(
                        file_generated_time, "%Y-%m-%d %H:%M:%S"
                    )
                    parsed_time = parsed_time.replace(
                        second=parsed_file_time.second
                    )
                except ValueError:
                    pass

            return parsed_time.strftime("%Y-%m-%d %H:%M:%S")

        return get_file_generated_time(file_path)

    except Exception as exc:
        logging.warning(
            f"Failed to extract JSON generated time from {file_path}: {exc}"
        )
        return "N/A"


def get_asc_measurement_window(asc_file_path):
    metadata = {
        "measurement_start": None,
        "first_event_offset": None,
        "last_event_offset": None,
    }

    try:
        with open(asc_file_path, "r", encoding="utf-8", errors="ignore") as asc_file:
            for raw_line in asc_file:
                line = raw_line.strip()
                if not line:
                    continue

                if metadata["measurement_start"] is None:
                    begin_match = re.match(
                        r"^Begin Triggerblock\s+(.+)$", line, re.IGNORECASE
                    )
                    if begin_match:
                        measurement_text = begin_match.group(1).strip()
                        try:
                            metadata["measurement_start"] = datetime.datetime.strptime(
                                measurement_text, "%a %b %d %H:%M:%S.%f %Y"
                            )
                        except ValueError as exc:
                            logging.warning(
                                f"Failed to parse ASC measurement start '{measurement_text}': {exc}"
                            )

                timestamp_match = re.match(r"^(?P<timestamp>\d+\.\d+)", line)
                if not timestamp_match:
                    continue

                timestamp = float(timestamp_match.group("timestamp"))
                if metadata["first_event_offset"] is None:
                    metadata["first_event_offset"] = timestamp
                metadata["last_event_offset"] = timestamp
    except Exception as exc:
        logging.warning(f"Failed to read ASC measurement window from {asc_file_path}: {exc}")

    return metadata


def format_time_with_offset(display_time, offset_seconds):
    if not display_time:
        return "N/A"
    if offset_seconds is None:
        return display_time
    return f"{display_time} ({offset_seconds:.5f})"


def to_time_display(dt_value):
    if not dt_value:
        return None
    return dt_value.strftime("%H:%M:%S.%f")[:-3]

def generate_html_report(messages_by_tc, output_path, asc_file_path, start_ts, end_ts, ecu_info_data=None, target_ecu=None, expected_ecu_fields=None, author_name="N/A", input_file_metadata=None, testcase_order=None, ecu_info_field_map=None, asc_did_responses=None, tester_name="N/A", input_json_file=None, placeholder_messages=None, test_start_time=None, test_end_time=None, branch_name="N/A", branch_url=""):
    def remove_padding(data_list, pad_byte):
        return [byte for byte in data_list if byte.upper() != pad_byte.upper()]

    def format_response_value(raw_resp, format_type, desc=""):
        raw_bytes = normalize_hex_bytes(raw_resp or [])
        clean_resp = remove_trailing_padding(raw_bytes, "AA")
        payload_bytes = normalize_response_payload(raw_bytes)
        format_type = (format_type or "Hex").strip().lower()

        try:
            full_hex_str = " ".join(clean_resp)
            payload = payload_bytes

            if "62" in [b.upper() for b in payload]:
                idx = next(i for i, b in enumerate(payload) if b.upper() == "62")
                payload = payload[idx + 3:] if len(payload) > idx + 2 else []
            elif len(payload) >= 2 and looks_like_did("".join(payload[:2])):
                payload = payload[2:]

            if not payload and is_empty_positive_read_response(raw_resp):
                return "ECU No response"

            special_value = decode_special_did_value(desc, payload)
            if special_value is not None:
                return special_value

            if format_type == "ascii":
                if payload and all(32 <= int(b, 16) <= 126 for b in payload):
                    return "".join(chr(int(b, 16)) for b in payload)
                return full_hex_str

            if format_type == "decimal":
                if payload:
                    return " ".join(str(int(b, 16)) for b in payload)
                return full_hex_str

            return full_hex_str
        except Exception:
            return " ".join(clean_resp)

    def build_ecu_info_from_messages():
        parsed = {}
        has_explicit_ecu_info = any(
            msg.get("tc_id", "").startswith("ECU_INFO")
            for steps in ordered_messages.values()
            for msg in steps
        )

        for steps in ordered_messages.values():
            for msg in steps:
                tc_id = msg.get("tc_id", "")
                desc = msg.get("desc", "")
                request_did = extract_request_did(msg.get("data_bytes", []))
                configured_field = did_to_label.get(request_did, "")

                if not desc and not configured_field:
                    continue

                if not tc_id.startswith("ECU_INFO") and not configured_field:
                    continue

                field_name = desc
                if configured_field and (not has_explicit_ecu_info or not tc_id.startswith("ECU_INFO")):
                    field_name = configured_field

                if not field_name:
                    continue

                response_type = msg.get("response_type", "Response Received")
                raw_resp = msg.get(
                    "response_data_bytes",
                    msg.get("response", {}).get("data_bytes", []),
                )
                payload = normalize_response_payload(raw_resp)

                valid_positive = raw_resp and len(payload) >= 3 and payload[0].upper() == "62"
                valid_did_data = (
                    raw_resp
                    and request_did
                    and len(payload) >= 2
                    and "".join(payload[:2]).upper() == request_did
                )

                if valid_positive or valid_did_data:
                    if is_empty_positive_read_response(raw_resp):
                        parsed.setdefault(
                            field_name,
                            format_response_value(raw_resp, msg.get("format", "Hex"), desc),
                        )
                    else:
                        parsed[field_name] = format_response_value(
                            raw_resp,
                            msg.get("format", "Hex"),
                            desc,
                        )
                elif response_type == "No Response":
                    parsed.setdefault(field_name, "ECU No response")
        return parsed

    def build_ecu_info_from_asc_dids():
        parsed = {}
        for did, raw_resp in (asc_did_responses or {}).items():
            field_name = did_to_label.get(did, "")
            if not field_name:
                continue

            desc = field_name
            parsed[field_name] = format_response_value(raw_resp, "Ascii", desc)
        return parsed

    ordered_messages = OrderedDict()
    testcase_order = testcase_order or []
    did_to_label, configured_ecu_fields = build_ecu_info_label_map(ecu_info_field_map)

    for occurrence_key in testcase_order:
        if occurrence_key in messages_by_tc:
            ordered_messages[occurrence_key] = messages_by_tc[occurrence_key]

    for occurrence_key, steps in messages_by_tc.items():
        if occurrence_key not in ordered_messages:
            ordered_messages[occurrence_key] = steps

    for occurrence_key in testcase_order:
        if (
            occurrence_key not in ordered_messages
            and placeholder_messages
            and occurrence_key in placeholder_messages
        ):
            ordered_messages[occurrence_key] = placeholder_messages[occurrence_key]

    def testcase_status(steps):
        # A retry must not mask an earlier timeout or response mismatch.
        if steps and all(msg.get("status") == "Pass" for msg in steps):
            return "Pass"
        return "Fail"

    total = len(ordered_messages)
    passed = sum(1 for tc in ordered_messages.values() if testcase_status(tc) == "Pass")
    failed = total - passed
    asc_window = get_asc_measurement_window(asc_file_path)
    start_offset = asc_window["first_event_offset"]
    if start_offset is None and isinstance(start_ts, (int, float)):
        start_offset = start_ts
    end_offset = asc_window["last_event_offset"]

    measurement_start = asc_window["measurement_start"]
    absolute_start_time = None
    if measurement_start is not None and start_offset is not None:
        absolute_start_time = measurement_start + datetime.timedelta(seconds=start_offset)
    elif test_start_time:
        absolute_start_time = test_start_time

    absolute_end_time = None
    if absolute_start_time is not None and start_offset is not None and end_offset is not None:
        absolute_end_time = absolute_start_time + datetime.timedelta(
            seconds=end_offset - start_offset
        )
    elif measurement_start is not None and end_offset is not None:
        absolute_end_time = measurement_start + datetime.timedelta(seconds=end_offset)
    elif test_end_time:
        absolute_end_time = test_end_time

    if start_offset is not None and end_offset is not None:
        duration = max(0.0, end_offset - start_offset)
    elif absolute_start_time and absolute_end_time:
        duration = (absolute_end_time - absolute_start_time).total_seconds()
    else:
        duration = 0.0

    test_start_display = format_time_with_offset(
        to_time_display(absolute_start_time),
        start_offset,
    )
    test_end_display = format_time_with_offset(
        to_time_display(absolute_end_time),
        end_offset,
    )

    asc_filename = os.path.basename(asc_file_path)
    html_filename = os.path.basename(output_path)
    input_filename = (
        input_file_metadata.get("filename")
        if input_file_metadata
        else "N/A"
    )
    input_generated_time = (
        input_file_metadata.get("generated_at")
        if input_file_metadata
        else "N/A"
    )
    html_generated_time = extract_generated_time_from_filename(output_path)
    if html_generated_time == "N/A":
        html_generated_time = get_file_generated_time(output_path)
    asc_generated_time = extract_generated_time_from_filename(asc_file_path)
    if asc_generated_time == "N/A":
        asc_generated_time = get_file_generated_time(asc_file_path)

    display_ecu_fields = list(expected_ecu_fields or [])
    for field in configured_ecu_fields:
        if field not in display_ecu_fields:
            display_ecu_fields.append(field)
    parsed_ecu_info_data = build_ecu_info_from_messages()
    asc_ecu_info_data = build_ecu_info_from_asc_dids()
    ecu_info_data = ecu_info_data or {}
    parsed_ecu_info_data = {
        field: value
        for field, value in parsed_ecu_info_data.items()
        if value is not None
    }
    asc_ecu_info_data = {
        field: value
        for field, value in asc_ecu_info_data.items()
        if value is not None
    }
    merged_ecu_info = merge_ecu_info_values(
        parsed_ecu_info_data,
        merge_ecu_info_values(
            asc_ecu_info_data,
            ecu_info_data,
            display_ecu_fields,
        ),
        display_ecu_fields,
    )
    ecu_info_lines = []
    if display_ecu_fields:
        for field in display_ecu_fields:
            value = merged_ecu_info.get(field)
            if value is None:
                value = "ECU No response"
            ecu_info_lines.append(
                f"<p><strong>{escape(field)}:</strong> {escape(value)}</p>"
            )
    else:
        ecu_info_lines = [
            f"<p><strong>{escape(k)}:</strong> {escape(v)}</p>"
            for k, v in merged_ecu_info.items()
        ]

    verdict_text = "Test passed" if failed == 0 else "Test failed"
    verdict_class = "overall-pass" if failed == 0 else "overall-fail"
    pass_pct = (passed / total * 100) if total else 0
    fail_pct = (failed / total * 100) if total else 0
    target_ecu_text = target_ecu or "N/A"
    input_json_name = os.path.basename(input_json_file) if input_json_file else "N/A"
    input_json_time = get_json_generated_time(input_json_file) if input_json_file else "N/A"
    app_version = "DTP-CAN Diagnostic Application V6.2.1"
    configuration_name = input_json_name if input_json_name != "N/A" else "N/A"

    def safe_text(value, default="N/A"):
        if value is None:
            return default
        return str(value)
        
    html = f"""<!DOCTYPE html>
<html>
<head><title>UDS Diagnostic Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  body {{ font-family: Arial, sans-serif; margin: 10px; color: #111; }}
  .report-title {{
    background: #d9d9d9;
    text-align: center;
    padding: 4px 0 5px;
    margin-bottom: 12px;
  }}
  .report-title h1 {{
    color: #111;
    font-size: 28px;
    margin: 0;
    font-weight: 700;
  }}
  .section-title {{
    background: #d9d9d9;
    text-align: center;
    font-weight: 700;
    padding: 6px;
    margin-top: 14px;
  }}
  .overall-row {{
    display: grid;
    grid-template-columns: 380px minmax(0, 1fr);
    align-items: center;
    gap: 12px;
    margin: 8px 0 14px;
  }}
  .overall-row h2 {{
    color: #111;
    margin: 0 0 0 60px;
    font-size: 16px;
    white-space: nowrap;
  }}
  .overall-bar {{
    height: 18px;
    line-height: 18px;
    color: #111;
    font-size: 16px;
    font-weight: 700;
    text-align: center;
  }}
  .overall-pass {{ background: #35a853; }}
  .overall-fail {{ background: #ee0000; }}
  .general-grid {{
    display: grid;
    grid-template-columns: minmax(520px, 1fr) minmax(420px, 520px);
    gap: 56px;
    max-width: 1280px;
    margin: 0 auto;
    padding: 16px 14px 24px;
  }}
  .info-block h3 {{
    margin: 0 0 10px;
    font-size: 14px;
  }}
  .info-table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 6px;
    font-size: 13px;
  }}
  .info-table td {{
    border: none !important;
    padding: 3px 6px;
    vertical-align: top;
  }}
  .info-table td:first-child {{
    width: 170px;
    font-weight: 700;
    white-space: nowrap;
  }}
  .overview-grid {{
    display: grid;
    grid-template-columns: minmax(520px, 1fr) 360px;
    gap: 56px;
    align-items: start;
    max-width: 1280px;
    margin: 0 auto;
    padding: 16px 14px;
  }}
  .stats-table {{
    width: 430px;
    border-collapse: collapse;
    font-size: 13px;
  }}
  .stats-table td, .stats-table th {{
    border: 1px solid #ccc;
    padding: 5px 8px;
  }}
  .stats-table th {{
    background: #eee;
    text-align: left;
  }}
  .pass {{ color: green; font-weight: bold; }}
  .fail {{ color: red; font-weight: bold; }}
  .chart-filter-row {{
    display: flex;
    align-items: center;
    gap: 18px;
    margin-top: 12px;
    margin-left: 24px;
    font-size: 14px;
  }}
  .chart-filter-item {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    user-select: none;
  }}
  .chart-filter-swatch {{
    width: 28px;
    height: 12px;
    display: inline-block;
  }}
  .chart-filter-label.inactive {{
    text-decoration: line-through;
    opacity: 0.6;
  }}
  #chart-container {{ width: 300px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
  th, td {{ border: 1px solid #ccc; padding: 8px; }}
  th {{ background: #f0f0f0; }}
  summary {{ font-weight: bold; cursor: pointer; }}
</style>
</head>
<body>

<div class="report-title">
    <h1>Report: DTP-CAN Diagnostic Test</h1>
</div>

<div class="overall-row">
    <h2>Overall Test Result Status</h2>
    <div class="overall-bar {verdict_class}">{verdict_text}</div>
</div>

<div class="section-title">General Test Information</div>
<div class="general-grid">
    <div class="info-block">
        <h3>Tester</h3>
        <table class="info-table">
            <tr><td>Tester Name</td><td>{escape(tester_name or "N/A")}</td></tr>
        </table>

        <h3 style="margin-top:18px;">Test Setup</h3>
        <table class="info-table">
            <tr><td>Version</td><td>{escape(app_version)}</td></tr>
            <tr>
                <td>Branch</td>
                <td>
                    <a href="{escape(branch_url)}" target="_blank">
                        {escape(branch_name)}
                    </a>
                </td>
            </tr>
            <tr><td>Testcase Author</td><td>{escape(author_name)}</td></tr>
            <tr><td>JSON Configuration File</td><td>{escape(format_generated_entry(input_json_name, input_json_time))}</td></tr>
            <tr><td>Generated Input File</td><td>{escape(format_generated_entry(input_filename, input_generated_time))}</td></tr>
            <tr><td>Output File, HTML Report</td><td>{escape(format_generated_entry(html_filename, html_generated_time))}</td></tr>
            <tr><td>Output File, ASC Report</td><td>{escape(format_generated_entry(asc_filename, asc_generated_time))}</td></tr>
        </table>
    </div>

    <div class="info-block">
        <h3>ECU Information</h3>
        <table class="info-table">
            <tr><td>Target ECU</td><td>{escape(target_ecu_text)}</td></tr>
            {"".join(f"<tr><td>{escape(safe_text(field))}</td><td>{escape(safe_text(merged_ecu_info.get(field), 'ECU No response'))}</td></tr>" for field in display_ecu_fields)}
        </table>
    </div>
</div>

<div class="section-title">Test Overview</div>
<div class="overview-grid">
    <div>
        <table class="info-table">
            <tr><td>Test start time</td><td>{test_start_display}</td></tr>
            <tr><td>Test end time</td><td>{test_end_display}</td></tr>
            <tr><td>Test duration</td><td>{duration:.3f} seconds</td></tr>
        </table>
        <table class="stats-table">
            <tr><th>Statistics</th><th>Count</th><th>Percentage</th></tr>
            <tr><td>Executed test cases</td><td>{total}</td><td>100%</td></tr>
            <tr><td>Test cases passed</td><td class="pass">{passed}</td><td class="pass">{pass_pct:.1f}%</td></tr>
            <tr><td>Test cases failed</td><td class="fail">{failed}</td><td class="fail">{fail_pct:.1f}%</td></tr>
        </table>
    </div>

    <div id="chart-container">
        <button type="button" onclick="showAllCases()">Show All</button>
        <canvas id="passFailChart" width="300" height="300"></canvas>
        <div class="chart-filter-row">
            <span class="chart-filter-item" onclick="setChartFilter('Passed')">
                <span class="chart-filter-swatch" style="background:#4CAF50;"></span>
                <span id="passedFilterLabel" class="chart-filter-label">Passed</span>
            </span>
            <span class="chart-filter-item" onclick="setChartFilter('Failed')">
                <span class="chart-filter-swatch" style="background:#F44336;"></span>
                <span id="failedFilterLabel" class="chart-filter-label">Failed</span>
            </span>
        </div>
    </div>
</div>

    <script>
        let activeFilter = null;

        function updateFilterLabels() {{
            const passedLabel = document.getElementById('passedFilterLabel');
            const failedLabel = document.getElementById('failedFilterLabel');

            passedLabel.classList.toggle('inactive', activeFilter === 'Failed');
            failedLabel.classList.toggle('inactive', activeFilter === 'Passed');
        }}

        function setChartFilter(label) {{
            activeFilter = label;
            filterCasesByLabel(label);
            updateFilterLabels();
            const filterIndex = chart.data.labels.indexOf(label);
            if (filterIndex >= 0) {{
                chart.setActiveElements([{{ datasetIndex: 0, index: filterIndex }}]);
            }}
            chart.update();
        }}

        function showAllCases() {{
            activeFilter = null;
            document.querySelectorAll('.case-block').forEach(el => {{
                el.style.display = 'block';
            }});
            chart.setActiveElements([]);
            updateFilterLabels();
            chart.update();
        }}

        function filterCasesByLabel(label) {{
            document.querySelectorAll('.case-block').forEach(el => {{
                el.style.display = 'none';
            }});
            if (label === 'Passed') {{
                document.querySelectorAll('.pass-case').forEach(el => {{
                    el.style.display = 'block';
                }});
            }} else if (label === 'Failed') {{
                document.querySelectorAll('.fail-case').forEach(el => {{
                    el.style.display = 'block';
                }});
            }}
        }}

        const ctx = document.getElementById('passFailChart').getContext('2d');
        const chart = new Chart(ctx, {{
            type: 'pie',
            data: {{
                labels: ['Passed', 'Failed'],
                datasets: [{{
                    data: [{passed}, {failed}],
                    backgroundColor: ['#4CAF50', '#F44336']
                }}]
            }},
            options: {{
                responsive: true,
                onClick: function (evt, item) {{
                    const segment = chart.getElementsAtEventForMode(evt, 'nearest', {{ intersect: true }}, true);
                    if (!segment.length) return;
                    const label = chart.data.labels[segment[0].index];
                    setChartFilter(label);
                }},
                plugins: {{
                    legend: {{ display: false }},
                    title: {{ display: true, text: 'Test Case Results' }}
                }}
            }}
        }});

        updateFilterLabels();
    </script>

    <hr><br>
    """

    for _occurrence_key, steps in ordered_messages.items():
        display_tc_id = steps[0].get("tc_id", "N/A") if steps else "N/A"
        status = testcase_status(steps)
        status_class = 'pass' if status == 'Pass' else 'fail' if status == 'Fail' else 'pending'
        html += f"<div class='case-block {status_class}-case'>\n"
        html += f"<details><summary>{display_tc_id} - <span class='{status_class}'>{status}</span></summary>\n"
        html += """<table><tr><th>Step</th><th>Description</th><th>Timestamp</th><th>Type</th><th>Data</th><th>Status</th><th>Failure Reason</th></tr>\n"""
        
        step_count = 1
        for msg in steps:
            desc = msg['desc']
            combined_desc = ""

            if "PreCondition:" in desc and "Testcase" in desc:
                parts = desc.split("PreCondition:", 1)[1].split("Testcase", 1)
                pre_detail = parts[0].strip()
                tc_detail = parts[1].strip()
                combined_desc = f"<b>PreCondition:</b> {escape(pre_detail)}<br><b>Testcase:</b>{escape(tc_detail)}"
            elif "PreCondition:" in desc:
                pre_detail = desc.split("PreCondition:", 1)[1].strip()
                combined_desc = f"<b>PreCondition:</b> {escape(pre_detail)}"
            else:
                combined_desc = escape(desc.strip())
            
            req_bytes = remove_trailing_padding(msg.get('data_bytes', []), "00")
            req_data = get_valid_request_data(msg.get('data_bytes', []))
            req_data_str = ' '.join(flatten_bytes(req_data))

            Expected_resp = msg.get('expected_resp', [])
            # Remove padding (AA and 00) from expected response
            E_clean_resp_t = remove_trailing_padding(Expected_resp, "00")
            E_clean_resp = remove_trailing_padding(E_clean_resp_t, "AA")
            Expected_resp_str = ' '.join(flatten_bytes(E_clean_resp))
            
            html += f"<tr><td>{step_count}</td><td>{escape(msg['desc'])}</td><td>{msg['timestamp']:.6f}</td><td>Request Sent</td><td>{req_data_str}</td><td></td><td>-</td></tr>\n"
            step_count += 1
            html += f"<tr><td>{step_count}</td><td></td><td></td><td>Expected_data</td><td>{Expected_resp_str}</td><td></td><td>-</td></tr>\n"
            step_count += 1

            response = msg.get("response", {})
            raw_resp = msg.get("response_data_bytes", response.get("data_bytes", []))
            # Keep zero bytes for DID values such as Manufacturing Date 00 00 00 00.
            clean_resp = remove_trailing_padding(raw_resp, "AA")
            payload_bytes = normalize_response_payload(raw_resp)
            format_type = msg.get("format", "Hex").strip().lower()
            response_type = msg.get("response_type", "Response Received")
            try:
                if is_empty_positive_read_response(raw_resp):
                    response_data_str = "ECU No response"
                else:
                    full_hex_str = ' '.join(payload_bytes if payload_bytes else clean_resp)
                    payload = payload_bytes

                    # Locate positive response SID in the UDS payload and skip SID + DID
                    if "62" in [b.upper() for b in payload]:
                        idx = next(i for i, b in enumerate(payload) if b.upper() == "62")
                        if len(payload) > idx + 2:
                            payload = payload[idx + 3:]
                        else:
                            payload = []

                    special_value = decode_special_did_value(msg.get("desc", ""), payload)

                    # Format conversion
                    if special_value is not None:
                        response_data_str = (
                            f"{full_hex_str} → {special_value}"
                            if special_value
                            else full_hex_str
                        )

                    elif format_type == "ascii":
                        ascii_str = ""
                        if payload and all(32 <= int(b, 16) <= 126 for b in payload):
                            ascii_str = ''.join(chr(int(b, 16)) for b in payload)
                        response_data_str = f"{full_hex_str} → {ascii_str}" if ascii_str else full_hex_str

                    elif format_type == "decimal":
                        decimal_str = ' '.join(str(int(b, 16)) for b in payload)
                        response_data_str = f"{full_hex_str} → {decimal_str}" if decimal_str else full_hex_str

                    else:  # default hex
                        response_data_str = full_hex_str

            except Exception:
                response_data_str = ' '.join(clean_resp)

            if response_type == "No Response":
                response_data_str = msg.get("response_note") or "ECU No response"
            elif response_type in ("Error Frame", "Empty Frame"):
                response_data_str = escape(response.get("raw", response_type))

            response_ts = response.get("timestamp")
            response_ts_str = f"{response_ts:.6f}" if isinstance(response_ts, (int, float)) else "-"
            html += f"<tr><td>{step_count}</td><td></td><td>{response_ts_str}</td><td>{escape(response_type)}</td><td>{response_data_str}</td><td>{msg['status']}</td><td>{escape(msg.get('failure_reason', ''))}</td></tr>\n"
            step_count += 1
        
        html += "</table></details></div>\n"

    html += "</body></html>"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"UDS HTML Report generated at:\n{output_path}\n")


@dataclass
class TestcaseDefinition:
    index: int
    tc_id: str
    occurrence_key: str
    desc: str
    request_payload: list
    request_keys: list
    expected_resp: list
    format_type: str
    step: tuple


class TestcaseMatcher:
    def __init__(self, definitions):
        self.definitions = definitions
        self.cursor = 0
        self.used_indices = set()

    def _mark_used(self, definition):
        self.used_indices.add(definition.index)
        self.cursor = max(self.cursor, definition.index + 1)
        return definition

    def has_matched_payload(self, request_payload):
        """Return whether this exact request was already consumed by a testcase.

        Once all matching definitions have been consumed, a repeated request in
        the ASC is a retry/duplicate capture, not another result to report.
        """
        return any(
            definition.index in self.used_indices
            and definition.request_payload == request_payload
            for definition in self.definitions
        )

    def _iter_candidates(self, start_from_cursor=True):
        if start_from_cursor:
            for idx in range(self.cursor, len(self.definitions)):
                if idx not in self.used_indices:
                    yield self.definitions[idx]
        for idx in range(0, len(self.definitions)):
            if idx >= self.cursor and start_from_cursor:
                continue
            if idx not in self.used_indices:
                yield self.definitions[idx]

    def _is_dynamic_security_access_key_request(self, definition, request_payload):
        expected = definition.request_payload or []
        if len(expected) != 2 or len(request_payload) <= len(expected):
            return False
        if expected[0] != "27" or request_payload[:2] != expected:
            return False
        try:
            return int(expected[1], 16) % 2 == 0
        except ValueError:
            return False

    def _match_dynamic_security_access_key_request(self, request_payload, start_from_cursor=True):
        for definition in self._iter_candidates(start_from_cursor=start_from_cursor):
            if self._is_dynamic_security_access_key_request(definition, request_payload):
                return self._mark_used(definition)
        return None

    def match(self, request_payload):
        if not request_payload:
            return None

        request_keys = build_request_candidate_keys(request_payload)
        for definition in self._iter_candidates(start_from_cursor=True):
            if definition.request_payload == request_payload:
                return self._mark_used(definition)

        for definition in self._iter_candidates(start_from_cursor=False):
            if definition.request_payload == request_payload:
                return self._mark_used(definition)

        dynamic_security_match = self._match_dynamic_security_access_key_request(
            request_payload,
            start_from_cursor=True,
        )
        if dynamic_security_match:
            return dynamic_security_match

        dynamic_security_match = self._match_dynamic_security_access_key_request(
            request_payload,
            start_from_cursor=False,
        )
        if dynamic_security_match:
            return dynamic_security_match

        # Real UDS requests must not be matched by partial prefixes like
        # 22 F1, otherwise retries for F18B can steal F18C/F193 testcases.
        if request_payload:
            return None

        for definition in self._iter_candidates(start_from_cursor=True):
            if any(key in request_keys for key in definition.request_keys):
                return self._mark_used(definition)

        for definition in self._iter_candidates(start_from_cursor=False):
            if any(key in request_keys for key in definition.request_keys):
                return self._mark_used(definition)

        return None


def build_testcase_definitions(txt_file_path):
    definitions = []
    occurrence_counts = defaultdict(int)

    running_index = 0
    for step in load_testcase_sequence(txt_file_path):
        if not step or step[0] == "WAIT":
            continue

        (
            step_tc_id,
            description,
            _sid,
            _sub,
            expected_response_data,
            _write_data,
            _addressing,
            format_type,
            *_rest,
        ) = step

        tc_id = step_tc_id.strip()
        occurrence_counts[tc_id] += 1
        request_payload = build_request_payload_from_step(step)
        definitions.append(
            TestcaseDefinition(
                index=running_index,
                tc_id=tc_id,
                occurrence_key=build_occurrence_key(tc_id, occurrence_counts[tc_id]),
                desc=description.strip(),
                request_payload=request_payload,
                request_keys=build_request_candidate_keys(request_payload),
                expected_resp=parse_expected_bytes(expected_response_data),
                format_type=(format_type or "Hex").strip().capitalize(),
                step=step,
            )
        )
        running_index += 1

    return definitions


def build_message_from_definition(definition, request_timestamp, request_bytes):
    addressing = ""
    if definition.step and len(definition.step) > 6:
        addressing = definition.step[6]

    return {
        "timestamp": request_timestamp,
        "can_id": "",
        "direction": "Tx",
        "data_bytes": payload_to_display_frame(request_bytes),
        "request_payload": request_bytes,
        "desc": definition.desc,
        "tc_id": definition.tc_id,
        "occurrence_key": definition.occurrence_key,
        "format": definition.format_type,
        "expected_resp": definition.expected_resp,
        "addressing": addressing,
        "status": "Pending",
    }


def build_unmatched_message(request_timestamp, request_bytes):
    return {
        "timestamp": request_timestamp,
        "can_id": "",
        "direction": "Tx",
        "data_bytes": payload_to_display_frame(request_bytes),
        "request_payload": request_bytes,
        "desc": "ASC diagnostic request not found in TXT testcase definitions",
        "tc_id": "UNMATCHED_ASC",
        "occurrence_key": f"UNMATCHED_ASC__{request_timestamp:.6f}",
        "format": "Hex",
        "expected_resp": [],
        "status": "Pending",
    }


def finalize_message(message, messages_by_tc, start_ts, end_ts, response=None, response_data_bytes=None, response_type=None, failure_reason=None, status=None):
    response = response or {}
    response_data_bytes = response_data_bytes or []
    response_type = response_type or "Response Received"

    if status is None and message.get("tc_id") == "UNMATCHED_ASC":
        status = "Fail"
        derived_reason = "Diagnostic traffic observed in ASC but not matched to TXT"
    elif status is None:
        status, derived_reason = get_status(response_data_bytes, message.get("expected_resp", []))
    else:
        derived_reason = ""

    message.update(
        {
            "response": response,
            "response_data_bytes": response_data_bytes,
            "response_type": response_type,
            "status": status,
            "failure_reason": failure_reason if failure_reason is not None else derived_reason,
        }
    )
    occurrence_key = message.get("occurrence_key", message["tc_id"])
    messages_by_tc[occurrence_key].append(message)

    start_ts = min(start_ts or message["timestamp"], message["timestamp"])
    response_ts = response.get("timestamp")
    if isinstance(response_ts, (int, float)):
        end_ts = max(end_ts or response_ts, response_ts)
    else:
        end_ts = max(end_ts or message["timestamp"], message["timestamp"])

    return start_ts, end_ts


def parse_asc_file_v2(asc_file_path, allowed_tx_ids, allowed_rx_ids, txt_file_path):
    definitions = build_testcase_definitions(txt_file_path)
    matcher = TestcaseMatcher(definitions)

    messages_by_tc = defaultdict(list)
    allowed_tx_ids = set(f"{id:X}" for id in allowed_tx_ids)
    allowed_rx_ids = set(f"{id:X}" for id in allowed_rx_ids)
    allowed_ids = allowed_tx_ids | allowed_rx_ids

    current_message = None
    request_builder = None
    response_builder = None
    pending_error_frame = None
    waiting_after_pending = False
    start_ts = None
    end_ts = None
    def close_current_no_response(reason, response=None, response_type=None, response_bytes=None):
        nonlocal current_message, start_ts, end_ts, pending_error_frame, response_builder, waiting_after_pending
        if not current_message:
            return
        start_ts, end_ts = finalize_message(
            current_message,
            messages_by_tc,
            start_ts,
            end_ts,
            response=response,
            response_data_bytes=response_bytes or [],
            response_type=response_type or "No Response",
            failure_reason=reason,
            status="Fail",
        )
        current_message = None
        pending_error_frame = None
        response_builder = None
        waiting_after_pending = False

    with open(asc_file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for line in lines:
        stripped = line.strip()
        if not stripped or not re.match(r"^\d+\.\d+", stripped):
            continue

        msg = parse_line(stripped)
        if not msg:
            continue

        if msg["frame_kind"] == "error":
            if current_message:
                pending_error_frame = msg
            continue

        if msg["can_id"] not in allowed_ids:
            continue

        data = msg["data_bytes"]
        if not data:
            continue

        direction = msg["direction"]
        pci = int(data[0], 16)
        frame_type = (pci >> 4) & 0x0F

        if direction == "Tx" and msg["can_id"] in allowed_tx_ids:
            if frame_type == 0x3:
                continue

            if frame_type == 0x0:
                request_payload = get_request_match_bytes(data)
                if (
                    current_message
                    and request_payload
                    and current_message.get("request_payload") == request_payload
                ):
                    pending_error_frame = None
                    response_builder = None
                    waiting_after_pending = False
                    continue

            if current_message and request_builder is None:
                reason = "Incomplete multi-frame response" if response_builder else "No response received"
                response = pending_error_frame if pending_error_frame else None
                response_type = "Error Frame" if pending_error_frame else "No Response"
                response_bytes = response_builder["payload"][:] if response_builder else []
                close_current_no_response(reason, response=response, response_type=response_type, response_bytes=response_bytes)

            if frame_type == 0x1 and len(data) >= 2:
                total_len = ((pci & 0x0F) << 8) | int(data[1], 16)
                request_builder = {
                    "timestamp": msg["timestamp"],
                    "can_id": msg["can_id"],
                    "payload": data[2:],
                    "total_len": total_len,
                }
                continue

            if request_builder and frame_type == 0x2:
                request_builder["payload"].extend(data[1:])
                if len(request_builder["payload"]) >= request_builder["total_len"]:
                    request_payload = request_builder["payload"][: request_builder["total_len"]]
                    definition = matcher.match(request_payload)
                    if definition:
                        current_message = build_message_from_definition(
                            definition,
                            request_builder["timestamp"],
                            request_payload,
                        )
                    elif matcher.has_matched_payload(request_payload):
                        # The matching testcase has already completed; this is
                        # a duplicate/retry transmission, not a new result.
                        pass
                    elif build_request_candidate_keys(request_payload):
                        current_message = build_unmatched_message(
                            request_builder["timestamp"],
                            request_payload,
                        )
                    request_builder = None
                continue

            request_builder = None
            request_payload = get_request_match_bytes(data)
            definition = matcher.match(request_payload)
            if definition:
                current_message = build_message_from_definition(
                    definition,
                    msg["timestamp"],
                    request_payload,
                )
            elif matcher.has_matched_payload(request_payload):
                # Do not add another report entry for a completed retry.
                pass
            elif build_request_candidate_keys(request_payload):
                current_message = build_unmatched_message(
                    msg["timestamp"],
                    request_payload,
                )
            continue

        if direction == "Rx" and msg["can_id"] in allowed_rx_ids and current_message:
            if frame_type == 0x3:
                continue

            payload = extract_isotp_payload(data)
            if len(payload) >= 3 and payload[0] == "7F" and payload[2] == "78":
                waiting_after_pending = True
                continue

            if frame_type == 0x1 and len(data) >= 2:
                total_len = ((pci & 0x0F) << 8) | int(data[1], 16)
                response_builder = {
                    "response": msg,
                    "payload": data[2:],
                    "total_len": total_len,
                    "observed_len": len(data[2:]),
                }
                continue

            if response_builder and frame_type == 0x2:
                response_builder["payload"].extend(data[1:])
                response_builder["observed_len"] = len(response_builder["payload"])
                if len(response_builder["payload"]) >= response_builder["total_len"]:
                    full_response = response_builder["payload"][: response_builder["total_len"]]
                    start_ts, end_ts = finalize_message(
                        current_message,
                        messages_by_tc,
                        start_ts,
                        end_ts,
                        response=response_builder["response"],
                        response_data_bytes=full_response,
                    )
                    current_message = None
                    response_builder = None
                    pending_error_frame = None
                    waiting_after_pending = False
                continue

            if response_builder:
                full_response = response_builder["payload"][: response_builder["total_len"]]
                failure_reason = None
                status = None
                if len(response_builder["payload"]) < response_builder["total_len"]:
                    failure_reason = (
                        f"Incomplete multi-frame response "
                        f"({len(response_builder['payload'])}/{response_builder['total_len']} bytes)"
                    )
                    status = "Fail"
                start_ts, end_ts = finalize_message(
                    current_message,
                    messages_by_tc,
                    start_ts,
                    end_ts,
                    response=response_builder["response"],
                    response_data_bytes=full_response,
                    failure_reason=failure_reason,
                    status=status,
                )
                current_message = None
                response_builder = None
                pending_error_frame = None
                waiting_after_pending = False

            start_ts, end_ts = finalize_message(
                current_message,
                messages_by_tc,
                start_ts,
                end_ts,
                response=msg,
                response_data_bytes=normalize_response_payload(data),
            )
            current_message = None
            pending_error_frame = None
            waiting_after_pending = False

    if current_message:
        reason = "Incomplete multi-frame response" if response_builder else "No response received"
        response = pending_error_frame if pending_error_frame else None
        response_type = "Error Frame" if pending_error_frame else "No Response"
        response_bytes = response_builder["payload"][:] if response_builder else []
        close_current_no_response(reason, response=response, response_type=response_type, response_bytes=response_bytes)

    return messages_by_tc, start_ts or 0, end_ts or 0

def generate_report(asc_file_path, txt_file_path, output_html_file, allowed_tx_ids, allowed_rx_ids, ecu_info_data=None, target_ecu=None, ecu_info_field_map=None, tester_name="N/A", input_json_file=None, test_start_time=None, test_end_time=None, branch_name="N/A", branch_url=""):
    global DESCRIPTION_MAP, DESCRIPTION_SEQUENCE
    DESCRIPTION_MAP = load_description_map(txt_file_path)
    DESCRIPTION_SEQUENCE = build_request_signature_sequence(txt_file_path)
    get_description.sequence = DESCRIPTION_SEQUENCE # type: ignore
    get_description.sequence_cursor = 0
    get_description.sequence_used_indices = set()
    testcase_order = get_testcase_order(txt_file_path)
    placeholder_messages = build_placeholder_messages(txt_file_path)
    expected_ecu_fields = get_expected_ecu_info_fields(txt_file_path)
    author_name = get_testcase_author(txt_file_path)
    input_file_metadata = get_testcase_generated_metadata(txt_file_path)

    messages_by_tc, start_ts, end_ts = parse_asc_file_v2(
        asc_file_path,
        allowed_tx_ids,
        allowed_rx_ids,
        txt_file_path,
    )
    messages_by_tc = ensure_all_testcases_present(messages_by_tc, txt_file_path)
    asc_did_responses = scan_actual_did_responses(
        asc_file_path,
        allowed_tx_ids,
        allowed_rx_ids,
    )

    report_path = output_html_file

    generate_html_report(
        messages_by_tc,
        report_path,
        asc_file_path,
        start_ts,
        end_ts,
        ecu_info_data,
        target_ecu,
        expected_ecu_fields,
        author_name,
        input_file_metadata,
        testcase_order,
        ecu_info_field_map,
        asc_did_responses,
        tester_name,
        input_json_file,
        placeholder_messages,
        test_start_time,
        test_end_time,
        branch_name,
        branch_url,
    )
