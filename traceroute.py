#!/usr/bin/env python3
import os
import csv
import time
import requests
import socket
from scapy.all import IP, UDP, sr1
import argparse
from concurrent.futures import ThreadPoolExecutor
import threading

socket.setdefaulttimeout(5)

asn_cache = {}
lock = threading.Lock()

def get_as_info(ip):
    if ip in asn_cache:
        return asn_cache[ip]
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        data = response.json()
        asn_cache[ip] = data
        return data
    except Exception:
        return {}

def read_targets():
    tranco = []
    with open("top-1m.csv", newline='') as csvfile:
        reader = list(csv.reader(csvfile))

        for i in range(1000):
            domain = reader[i][1].strip() if len(reader[i]) > 1 else reader[i][0].strip()
            tranco.append((domain, "tranco-top1k"))

        for i in range(10000, 11500):
            domain = reader[i][1].strip() if len(reader[i]) > 1 else reader[i][0].strip()
            tranco.append((domain, "tranco-rank10k"))

        for i in range(100000, 101500):
            domain = reader[i][1].strip() if len(reader[i]) > 1 else reader[i][0].strip()
            tranco.append((domain, "tranco-rank100k"))

    vultr = [
        ("139.84.226.78", "Johannesburg"), ("139.84.130.100", "Bangalore"), ("139.84.162.104", "Delhi NCR"),
        ("65.20.66.100", "Mumbai"), ("64.176.34.94", "Osaka"), ("141.164.34.61", "Seoul"),
        ("45.32.100.168", "Singapore"), ("64.176.162.16", "Tel Aviv"), ("108.61.201.151", "Tokyo"),
        ("67.219.110.24", "Melbourne"), ("108.61.212.117", "Sydney"), ("108.61.198.102", "Amsterdam"),
        ("108.61.210.117", "Frankfurt"), ("108.61.196.101", "London"), ("208.76.222.30", "Madrid"),
        ("64.176.178.136", "Manchester"), ("108.61.209.127", "Paris"), ("70.34.194.86", "Stockholm"),
        ("70.34.242.24", "Warsaw"), ("108.61.193.166", "Atlanta"), ("107.191.51.12", "Chicago"),
        ("108.61.224.175", "Dallas"), ("208.72.154.76", "Honolulu"), ("108.61.219.200", "Los Angeles"),
        ("216.238.66.16", "Mexico City"), ("104.156.244.232", "Miami"), ("108.61.149.182", "New Jersey"),
        ("108.61.194.105", "Seattle"), ("104.156.230.107", "Silicon Valley"), ("149.248.50.81", "Toronto"),
        ("64.176.2.7", "Santiago"), ("216.238.98.118", "Sao Paulo")
    ]
    vultr_targets = [(ip, f"vultr-{location}") for ip, location in vultr]
    return tranco + vultr_targets

def traceroute(destination, source_label, max_hops=30, timeout=2, writer=None, probes_per_hop=3):
    try:
        destination_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        time.sleep(1)
        try:
            destination_ip = socket.gethostbyname(destination)
        except socket.gaierror:
            with lock:
                print(f"DNS failed twice for {destination}, skipping.")
                writer.writerow([destination, "N/A", "N/A", "Unresolvable", "", "", "", "", "", "", "", "", "", "", source_label])
            return

    port = 33434
    ttl = 1
    any_response = False

    print(f"\nTraceroute to {destination} [{destination_ip}] (max hops: {max_hops}, timeout: {timeout}s):")
    print("".join(["Dest".ljust(30), "Hop".ljust(5), "Responder IP".ljust(20), "Org (ASN)".ljust(35),
                   "RTT1".ljust(10), "RTT2".ljust(10), "RTT3".ljust(10)]))

    while ttl <= max_hops:
        rtts, responder_ip, responder_info = [], None, {}
        for _ in range(probes_per_hop):
            packet = IP(dst=destination_ip, ttl=ttl) / UDP(dport=port)
            reply = sr1(packet, timeout=timeout, verbose=0)

            if reply:
                any_response = True
                try:
                    rtt = round((reply.time - packet.sent_time) * 1000, 2)
                except AttributeError:
                    rtt = "*"
                if not responder_ip:
                    responder_ip = reply.src
                    responder_info = get_as_info(responder_ip)
                rtts.append(rtt)
            else:
                rtts.append("*")

        org_display = responder_info.get("org", "N/A") if responder_ip else ""
        rtt_strs = [(f"{x} ms" if isinstance(x, float) else "*") for x in rtts]

        with lock:
            print("".join([
                destination.ljust(30), str(ttl).ljust(5),
                (responder_ip or "*").ljust(20), org_display.ljust(35),
                rtt_strs[0].ljust(10), rtt_strs[1].ljust(10), rtt_strs[2].ljust(10)
            ]))
            writer.writerow([
                destination, destination_ip, ttl, responder_ip or "*", org_display,
                responder_info.get("city", ""), responder_info.get("region", ""),
                responder_info.get("country", ""), responder_info.get("loc", ""),
                responder_info.get("postal", ""), responder_info.get("timezone", ""),
                rtts[0] if isinstance(rtts[0], float) else "*",
                rtts[1] if isinstance(rtts[1], float) else "*",
                rtts[2] if isinstance(rtts[2], float) else "*",
                source_label
            ])

        if reply and reply.type == 3:
            break
        ttl += 1

    if not any_response:
        with lock:
            writer.writerow([
                destination, destination_ip, "N/A", "All hops timeout", "", "", "", "", "", "", "", "", "", "", source_label
            ])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--max-hops", type=int, default=30)
    parser.add_argument("-t", "--timeout", type=int, default=2)
    parser.add_argument("-j", "--threads", type=int, default=50)
    parser.add_argument("-d", "--delay", type=float, default=0.1)
    args = parser.parse_args()

    targets = read_targets()
    with open("traceroute_log_rtt.csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Destination", "Destination IP", "Hop", "IP", "ASN", "City", "Region", "Country",
                         "Loc", "Postal", "Timezone", "RTT1", "RTT2", "RTT3", "Source"])
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = []
            for dest, label in targets:
                futures.append(executor.submit(traceroute, dest, label, args.max_hops, args.timeout, writer))
                time.sleep(args.delay)
            for future in futures:
                future.result()

    # Mark completion
    with open("traceroute_finished.txt", "w") as done_file:
        done_file.write("Traceroute measurements completed.\n")

if __name__ == "__main__":
    main()
