from __future__ import annotations


def trace_victim_chain(
    fraud_txid: str,
    recipient_address: str,
    rpc,
    conn,
    *,
    get_tx,
    save_tx_to_db,
    get_tx_block_info,
    get_spending_info,
    get_tx_outputs,
    check_address,
    is_acam_burdenable_attribution,
    logger,
    max_hops: int = 8,
) -> list:
    """
    Verfolgt den Pfad des gestohlenen Geldes ab der Empfänger-Adresse.

    Korrekte Logik fuer Splits:
    - Queue: (from_txid, tracked_address, tracked_amount, hop_idx)
    - Verfolgt ALLE Outputs einer TX die ueber Dust-Limit liegen
    - Jeder Pfad endet bei Exchange, Pooling oder unspent UTXO
    - visited_spending_txids verhindert Schleifen

    Jede Adresse wird frisch geprüft. Es gibt keinen fachlichen Exchange-Cache,
    der einen aktuellen Falllauf vorzeitig beeinflusst.
    """
    hops = []
    visited_spending_txids = set()

    fraud_tx_data = get_tx(fraud_txid, rpc)
    recipient_amount = 0.0
    if fraud_tx_data:
        for vout in fraud_tx_data.get("vout", []):
            addr = vout.get("scriptPubKey", {}).get("address") or vout.get("scriptpubkey_address")
            if addr == recipient_address:
                val = vout.get("value", 0)
                recipient_amount = val if isinstance(val, float) and val < 100 else val / 1e8
                break

    queue = [(fraud_txid, recipient_address, recipient_amount, 1)]

    while queue and len(hops) < max_hops:
        current_txid, current_address, from_amount, hop_idx = queue.pop(0)
        logger.info(
            f"  TRACER: hop={hop_idx}, addr={current_address[:20]}..., "
            f"txid={current_txid[:16]}, queue_remaining={len(queue)}"
        )

        current_tx = get_tx(current_txid, rpc)
        if not current_tx:
            logger.info("  TRACER: TX not found, skip")
            continue
        save_tx_to_db(current_txid, current_tx, conn)

        vout_idx = None
        actual_from_amount = from_amount
        for i, vout in enumerate(current_tx.get("vout", [])):
            addr = vout.get("scriptPubKey", {}).get("address") or vout.get("scriptpubkey_address")
            if addr == current_address:
                vout_idx = i
                val = vout.get("value", 0)
                actual_from_amount = val if isinstance(val, float) and val < 100 else val / 1e8
                break

        if vout_idx is None:
            logger.info(f"  TRACER: vout_idx None for {current_address[:20]}, skip")
            continue

        spend_state, spending_txid = get_spending_info(current_txid, vout_idx, rpc)
        logger.info(
            f"  TRACER: spend_state={spend_state}, "
            f"spending_txid={spending_txid[:16] if spending_txid else 'None'} "
            f"für {current_txid[:16]}:{vout_idx}"
        )
        if spend_state == "unspent":
            check = check_address(current_address)
            if is_acam_burdenable_attribution(check) and hops:
                for hop in reversed(hops):
                    if any(a == current_address for a, _ in hop.get("to_addresses", [])):
                        hop["confidence"] = "L2"
                        hop["confidence_label"] = "Forensically corroborated"
                        hop["exchange"] = check["exchange"]
                        hop["exchange_wallet_id"] = check.get("wallet_id", "")
                        hop["exchange_source"] = check.get("source", "")
                        hop["label"] = f"Exchange deposit -> {check['exchange']}"
                        hop["method"] = (
                            f"Exchange Intel Agent attribution ({check.get('label', '')})"
                        )
                        hop["notes"] += f" Address identified as {check['exchange']}."
                        hop["chain_end_reason"] = "exchange"
                        break
            else:
                if hops:
                    for hop in reversed(hops):
                        if any(a == current_address for a, _ in hop.get("to_addresses", [])):
                            hop["chain_end_reason"] = "unspent"
                            hop["notes"] += (
                                f" UTXO at {current_address[:20]}... remains unspent "
                                f"(as of the analysis timestamp). Funds may still be recoverable."
                            )
                            break
            continue
        if spend_state in {"spent_unresolved", "unknown"}:
            resolution_note = (
                " The output was demonstrably spent, but the spending transaction could not be loaded conclusively "
                "with the current spend-resolution path."
                if spend_state == "spent_unresolved"
                else
                " Spend resolution was technically incomplete; the next hop could not be determined reliably."
            )
            if hops:
                for hop in reversed(hops):
                    if any(a == current_address for a, _ in hop.get("to_addresses", [])):
                        hop["chain_end_reason"] = "lookup_incomplete"
                        hop["notes"] += resolution_note
                        break
            else:
                block_height, ts_str = get_tx_block_info(current_tx)
                hops.append(
                    {
                        "hop": hop_idx,
                        "label": "Forwarding path not fully resolved",
                        "txid": current_txid,
                        "block": block_height or 0,
                        "timestamp": ts_str,
                        "from_addresses": [(current_address, actual_from_amount)],
                        "to_addresses": [(current_address, actual_from_amount)],
                        "fee_btc": None,
                        "confidence": "L1",
                        "confidence_label": "Mathematically proven",
                        "method": "Direct UTXO link to recipient; spend resolution incomplete",
                        "notes": (
                            "Receipt by this address is proven on-chain."
                            + resolution_note
                            + " The report is technically incomplete at this point and must not be interpreted as an unspent conclusion."
                        ),
                        "is_sanctioned": False,
                        "chain_end_reason": "lookup_incomplete",
                        "exchange_addresses": [],
                    }
                )
            continue

        if spending_txid in visited_spending_txids:
            logger.info(f"  TRACER: SKIP — {spending_txid[:16]} already visited")
            continue
        visited_spending_txids.add(spending_txid)

        spending_tx = get_tx(spending_txid, rpc)
        if not spending_tx:
            logger.warning(
                f"  TRACER: spending_tx {spending_txid[:16]} could not be loaded, skip"
            )
            continue
        save_tx_to_db(spending_txid, spending_tx, conn)

        to_block, ts_str = get_tx_block_info(spending_tx)
        to_outputs = get_tx_outputs(spending_tx)

        exchange_hits = {}
        sanctioned = False
        for addr, _ in to_outputs:
            if addr == current_address:
                continue
            check = check_address(addr, use_downstream=False)
            if is_acam_burdenable_attribution(check):
                exchange_hits[addr] = check
            if check.get("is_sanctioned"):
                sanctioned = True

        dust_limit = 0.00000546
        max_output = max((btc for _, btc in to_outputs), default=0)
        pooling_detected = (
            actual_from_amount > 0
            and max_output > actual_from_amount * 3.0
            and not exchange_hits
        )

        max_branch_outputs = 5
        relevant_outputs = []
        non_exchange_outputs = []
        for addr, btc in to_outputs:
            if addr == current_address:
                non_exchange_outputs.append((addr, btc, False))
            elif addr in exchange_hits:
                relevant_outputs.append((addr, btc, True))
            elif btc > dust_limit:
                non_exchange_outputs.append((addr, btc, False))

        non_exchange_outputs.sort(key=lambda x: x[1], reverse=True)
        relevant_outputs.extend(non_exchange_outputs[:max_branch_outputs])

        if not relevant_outputs and to_outputs:
            best = max(to_outputs, key=lambda x: x[1])
            relevant_outputs = [(best[0], best[1], False)]

        display_outputs = [(addr, btc) for addr, btc, _ in relevant_outputs]

        if exchange_hits:
            ex_names = ", ".join(set(c["exchange"] for c in exchange_hits.values()))
            label = f"Exchange deposit -> {ex_names}"
            first_ex = next(iter(exchange_hits.values()))
            method = f"Exchange Intel Agent attribution ({first_ex.get('label', '')})"
            notes = f"Stolen funds flow into {ex_names}. Identified via {first_ex['source']}."
            confidence = "L2"
        elif pooling_detected:
            label = "Consolidation — forwarding path no longer uniquely attributable"
            method = "Direct UTXO link (input), pooling detected (output)"
            notes = (
                f"Incoming amount {actual_from_amount:.8f} BTC was consolidated with third-party funds "
                f"(output: {max_output:.8f} BTC). "
                f"Mathematical attribution of the stolen funds is no longer possible beyond this point. "
                f"This is consistent with exchange-internal consolidation or a mixing workflow."
            )
            confidence = "L2"
        else:
            label = "UTXO forwarding"
            method = "Direct UTXO link"
            notes = "Automatically identified via the local node and Blockstream."
            confidence = "L1"

        if sanctioned:
            notes += " SANCTIONED ADDRESS (OFAC SDN)."

        if exchange_hits:
            chain_end_reason = "exchange"
        elif pooling_detected:
            chain_end_reason = "pooling"
        else:
            chain_end_reason = None

        hop = {
            "hop": hop_idx,
            "label": label,
            "txid": spending_txid,
            "block": to_block or 0,
            "timestamp": ts_str,
            "from_addresses": [(current_address, actual_from_amount)],
            "to_addresses": display_outputs,
            "fee_btc": None,
            "confidence": confidence,
            "confidence_label": "Forensically corroborated" if confidence == "L2" else "Mathematically proven",
            "method": method,
            "notes": notes,
            "is_sanctioned": sanctioned,
            "chain_end_reason": chain_end_reason,
            "exchange_addresses": list(exchange_hits.keys()),
            "exchange_details": {
                addr: {
                    "exchange": info.get("exchange"),
                    "wallet_id": info.get("wallet_id", ""),
                    "source": info.get("source", ""),
                    "label": info.get("label", ""),
                }
                for addr, info in exchange_hits.items()
            },
        }

        if exchange_hits:
            first_ex_addr = next(iter(exchange_hits))
            first_ex = exchange_hits[first_ex_addr]
            hop["exchange"] = first_ex["exchange"]
            hop["exchange_wallet_id"] = first_ex.get("wallet_id", "")
            hop["exchange_source"] = first_ex.get("source", "")

        hops.append(hop)
        logger.info(
            f"  TRACER: HOP {hop_idx} built: {label[:50]}, "
            f"exchange_hits={list(exchange_hits.keys())[:3]}, pooling={pooling_detected}"
        )

        if not pooling_detected:
            for addr, btc, is_exchange in relevant_outputs:
                if not is_exchange:
                    logger.info(
                        f"  TRACER: QUEUE += ({spending_txid[:16]}, {addr[:20]}, "
                        f"{btc:.8f}, hop={hop_idx + 1})"
                    )
                    queue.append((spending_txid, addr, btc, hop_idx + 1))
        else:
            logger.info("  TRACER: POOLING — no further forwarding")

    seen = set()
    unique_hops = []
    for hop in sorted(hops, key=lambda h: (h["hop"], h["txid"])):
        key = (hop["txid"], hop["from_addresses"][0][0] if hop["from_addresses"] else "")
        if key not in seen:
            seen.add(key)
            unique_hops.append(hop)
    for i, hop in enumerate(unique_hops):
        hop["hop"] = i + 1

    return unique_hops
