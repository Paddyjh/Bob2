import os
import argparse
import subprocess
import re
import csv


def ipv4_to_ipv6(ipv4):
    """Convert an IPv4 address to IPv6 using the ::ffff: method."""
    return "::ffff:{}".format(ipv4)


def ping_with_response_time(ipv4, timeout=1):
    """Ping an IPv4 address and return the response time in ms."""
    try:
        output = subprocess.check_output(
            "ping -c 1 -W {} {}".format(timeout, ipv4),
            shell=True,
            text=True,
            stderr=subprocess.DEVNULL
        )
        match = re.search(r'time=(\d+\.\d+) ms', output)
        if match:
            return float(match.group(1))
        return None
    except subprocess.CalledProcessError:
        return None  # Ping failed or timeout


def get_http_response(ipv4, curl_addr):
    """Make an HTTP request using curl and return the response message if status code is 200."""
    try:
        # Log to indicate progress
        print(f"Attempting HTTP request to {curl_addr} (IP: {ipv4})...")
        # First check the HTTP status code
        output = subprocess.check_output(
            f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 3 --connect-timeout 2 {
                curl_addr}",
            shell=True,
            text=True,
            stderr=subprocess.DEVNULL
        )
        if output.strip() == "200":
            print(f"HTTP 200 OK from {curl_addr}")
            response_body = subprocess.check_output(
                f"curl -s --max-time 3 {curl_addr}",
                shell=True,
                text=True,
                stderr=subprocess.DEVNULL
            )
            return response_body.strip()
        else:
            print(f"HTTP request to {
                  curl_addr} failed with status: {output.strip()}")
            return f"No Response (HTTP {output.strip()})"
    except subprocess.CalledProcessError:
        print(f"Failed to connect to {curl_addr}")
        # For curl failures or unreachable IPs
        return "No Response (Connection Failed)"


def main(ping_ip, curl_addr, output_csv):
    results = []
    for ip in range(1, 50):  # Example scan of 50 IPs, adjust range as needed
        ipv4 = "{}.{}".format(ping_ip, ip)
        print(f"Pinging {ipv4}...")
        response_time = ping_with_response_time(ipv4)
        if response_time is not None:
            print(f"{ipv4} is active. Fetching HTTP response...")
            ipv6 = ipv4_to_ipv6(ipv4)
            http_response = get_http_response(ipv4, curl_addr)
            results.append({
                "IPv4": ipv4,
                "IPv6": ipv6,
                "Response Time (ms)": response_time,
                "HTTP Response": http_response
            })
        else:
            print(f"{ipv4} did not respond. Skipping HTTP request.")

    # Sort results by response time
    sorted_results = sorted(results, key=lambda x: x["Response Time (ms)"])

    # Write results to CSV
    with open(output_csv, "w", newline="") as csvfile:
        fieldnames = ["IPv4", "IPv6", "Response Time (ms)", "HTTP Response"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(sorted_results)

    print(f"CSV file '{output_csv}' has been created.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ping sweep for a given network and save results to CSV.")
    parser.add_argument("--ping_ip", required=True,
                        help="Base IP address for ping (e.g., 192.168.1)")
    parser.add_argument("--curl_addr", required=True,
                        help="Full URL for curl (e.g., http://example.com:port)")
    parser.add_argument("--output_csv", required=True,
                        help="Output CSV file name (e.g., results.csv)")
    args = parser.parse_args()

    main(args.ping_ip, args.curl_addr, args.output_csv)
