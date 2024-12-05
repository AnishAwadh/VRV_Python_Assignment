import re
import csv
from collections import defaultdict, Counter

# Configuration
FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"

def parse_log_file(file_path):
    """Reads the log file and returns a list of log entries."""
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def count_requests_per_ip(logs):
    """Counts the number of requests per IP address."""
    ip_counts = Counter()
    for log in logs:
        ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
        if ip_match:
            ip = ip_match.group(1)
            ip_counts[ip] += 1
    return ip_counts

def find_most_accessed_endpoint(logs):
    """Finds the most frequently accessed endpoint."""
    endpoint_counts = Counter()
    for log in logs:
        endpoint_match = re.search(r'"[A-Z]+\s+(/[^\s]*)', log)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_counts[endpoint] += 1
    return endpoint_counts.most_common(1)[0] if endpoint_counts else ("N/A", 0)

def detect_suspicious_activity(logs):
    """Detects IP addresses with failed login attempts exceeding the threshold."""
    failed_attempts = defaultdict(int)
    for log in logs:
        if '401' in log or "Invalid credentials" in log:
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
            if ip_match:
                ip = ip_match.group(1)
                failed_attempts[ip] += 1
    flagged_ips = {ip: count for ip, count in failed_attempts.items() if count > FAILED_LOGIN_THRESHOLD}
    return flagged_ips

def save_results_to_csv(ip_requests, most_accessed, suspicious_ips):
    """Saves the results to a CSV file."""
    with open(OUTPUT_FILE, 'w', newline='') as file:
        writer = csv.writer(file)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed)

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    """Main function to process the log file and output results."""
    logs = parse_log_file(LOG_FILE)

    # Analyze logs
    ip_requests = count_requests_per_ip(logs)
    most_accessed = find_most_accessed_endpoint(logs)
    suspicious_ips = detect_suspicious_activity(logs)

    # Display results
    print("Requests per IP:")
    for ip, count in ip_requests.items():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save to CSV
    save_results_to_csv(ip_requests, most_accessed, suspicious_ips)
    print(f"\nResults saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
