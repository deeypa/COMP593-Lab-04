#!/usr/bin/env python3

"""
This script processes a network firewall log file, extracts information about invalid users and
destination ports, and produces CSV and plain text report files.
"""

import re
import os
import pd


def get_log_file_path(param_num):
    """
    Gets the log file path from the command line parameters.

    :param param_num: The parameter number from which to get the log file path.
    :type param_num: int
    :raises TypeError: if param_num is not an integer.
    :raises ValueError: if param_num is not a valid command line parameter number.
    :raises FileNotFoundError: if the log file path does not exist.
    :returns: The path to the log file.
    :rtype: str
    """

    if not isinstance(param_num, int):
        raise TypeError("param_num must be an integer")

    if param_num < 1 or param_num > len(sys.argv) - 1:
        raise ValueError("param_num must be a valid command line parameter number")

    log_file_path = sys.argv[param_num]

    if not os.path.exists(log_file_path):
        raise FileNotFoundError("Log file path does not exist: {}".format(log_file_path))

    return log_file_path


def filter_log_records(log_file_path, regex, case_sensitive=False,
                       print_records=False, print_summary=False):
    """
    Filters log records that match a specified regex.

    :param log_file_path: The path to the log file.
    :type log_file_path: str
    :param regex: The regular expression to match.
    :type regex: str
    :param case_sensitive: Whether to perform a case-sensitive match.
    :type case_sensitive: bool
    :param print_records: Whether to print the records that match the regex.
    :type print_records: bool
    :param print_summary: Whether to print a summary sentence.
    :type print_summary: bool
    :raises TypeError: if any of the parameters are of the wrong type.
    :raises ValueError: if any of the parameters are invalid.
    :returns: A list of all records that match the regex.
    :rtype: list
    """

    if not isinstance(log_file_path, str):
        raise TypeError("log_file_path must be a string")

    if not isinstance(regex, str):
        raise TypeError("regex must be a string")

    if not isinstance(case_sensitive, bool):
        raise TypeError("case_sensitive must be a boolean")

    if not isinstance(print_records, bool):
        raise TypeError("print_records must be a boolean")

    if not isinstance(print_summary, bool):
        raise TypeError("print_summary must be a boolean")

    matching_records = []

    with open(log_file_path, "r") as log_file:
        for line in log_file:
            if case_sensitive:
                match = re.search(regex, line)
            else:
                match = re.search(regex, line, re.IGNORECASE)

            if match:
                matching_records.append(line.strip())

                if print_records:
                    print(line.strip())

    if print_summary:
        if case_sensitive:
            match_type = "case-sensitive"
        else:
            match_type = "case-insensitive"

        print("The log file contains {} records that {} match the regex '{}'.".format(
            len(matching_records), match_type, regex))

    return matching_records


def extract_data(log_file_path, regex, print_records=False):
    """
    Extracts data from log records that match a specified regex with capture groups.

    :param log_file_path: The path to the log file.
    :type log_file_path: str
    :param regex: The regular expression to match.
    :type regex: str
    :param print_records: Whether to print the extracted data.
    :type print_records: bool
    :raises TypeError: if any of the parameters are of the wrong type.
    :raises ValueError: if any of the parameters are invalid.
    :returns: A list of tuples containing the extracted data.
    :rtype: list
    """

    if not isinstance(log_file_path, str):
        raise TypeError("log_file_path must be a string")

    if not isinstance(regex, str):
        raise TypeError("regex must be a string")

    if not isinstance(print_records, bool):
        raise TypeError("print_records must be a boolean")

    extracted_data = []

    with open(log_file_path, "r") as log_file:
        for line in log_file:
            match = re.search(regex, line)

            if match:
                extracted_data.append(match.groups())

                if print_records:
                    print(match.groups())

    return extracted_data


def tally_traffic_by_port(log_file_path):
    """
    Tallies the number of records that contain each destination port number.

    :param log_file_path: The path to the log file.
    :type log_file_path: str
    :raises TypeError: if log_file_path is not a string.
    :raises ValueError: if log_file_path does not exist.
    :returns: A dictionary of destination port number records counts.
    :rtype: dict
    """

    if not isinstance(log_file_path, str):
        raise TypeError("log_file_path must be a string")

    if not os.path.exists(log_file_path):
        raise ValueError("Log file path does not exist: {}".format(log_file_path))

    port_counts = {}

    with open(log_file_path, "r") as log_file:
        for line in log_file:
            match = re.search(r"DPT=(\d+)", line)

            if match:
                port_number = int(match.group(1))

                if port_number in port_counts:
                    port_counts[port_number] += 1
                else:
                    port_counts[port_number] = 1

    return port_counts


def generate_destination_port_report(log_file_path, destination_port):
    """
    Generates a CSV report file containing information extracted from log records that
    contain a specified destination port number.

    :param log_file_path: The path to the log file.
    :type log_file_path: str
    :param destination_port: The destination port number.
    :type destination_port: int
    :raises TypeError: if any of the parameters are of the wrong type.
    :raises ValueError: if any of the parameters are invalid.
    """

    if not isinstance(log_file_path, str):
        raise TypeError("log_file_path must be a string")

    if not isinstance(destination_port, int):
        raise TypeError("destination_port must be an integer")

    data = []

    with open(log_file_path, "r") as log_file:
        for line in log_file:
            match = re.search(r"DPT={}".format(destination_port), line)

            if match:
                match_data = re.findall(
                    r"DATE=(\d+-\w+-\d+).*TIME=(\d+:\d+:\d+).*SRC=(\d+\.\d+\.\d+\.\d+).*DST=(\d+\.\d+\.\d+\.\d+).*SPT=(\d+)",
                    line
                )

                data.append(match_data[0])

    df = pd.DataFrame(data, columns=[
        "Date", "Time", "Source IP Address", "Destination IP Address", "Source Port",
        "Destination Port"
    ])

    report_file_path = os.path.join(
        os.path.dirname(log_file_path),
        "destination_port_{}_report.csv".format(destination_port)
    )

    df.to_csv(report_file_path, index=False)


def generate_invalid_user_report(log_file_path):
    """
    Generates a CSV report file containing information extracted from log records that
    indicate an attempt to login as an invalid user.

    :param log_file_path: The path to the log file.
    :type log_file_path: str
    :raises TypeError: if log_file_path is not a string.
    :raises ValueError: if log_file_path does not exist.
    """

    if not isinstance(log_file_path, str):
        raise TypeError("log_file_path must be a string")

    if not os.path.exists(log_file_path):
        raise ValueError("Log file path does not exist: {}".format(log_file_path))

    data = []

    with open(log_file_path, "r") as log_file:
        for line in log_file:
            match = re.search(r"Invalid user.*", line)

            if match:
                match_data = re.findall(
                    r"DATE=(\d+-\w+-\d+).*TIME=(\d+:\d+:\d+).*Invalid user (\w+).*from (\d+\.\d+\.\d+\.\d+)",
                    line
                )

                data.append(match_data[0])

    df = pd.DataFrame(data, columns=["Date", "Time", "Username", "IP Address"])

    report_file_path = os.path.join(os.path.dirname(log_file_path), "invalid_users.csv")

    df.to_csv(report_file_path, index=False)


def generate_source_ip_log(log_file_path, source_ip):
    """
    Generates a plain text log file containing log records that contain a specified source IP
    address.

    :param log_file_path: The path to the log file.
    :type log_file_path: str
    :param source_ip: The source IP address.
    :type source_ip: str
    :raises TypeError: if any of the parameters are of the wrong type.
    :raises ValueError: if any of the parameters are invalid.
    """

    if not isinstance(log_file_path, str):
        raise TypeError("log_file_path must be a string")

    if not isinstance(source_ip, str):
        raise TypeError("source_ip must be a string")

    if not re.match(r"\d+\.\d+\.\d+\.\d+", source_ip):
        raise ValueError("source_ip must be a valid IP address")

    with open(log_file_path, "r") as log_file:
        with open(os.path.join(
            os.path.dirname(log_file_path),
            "source_ip_{}.log".format(source_ip.replace(".", "_"))
        ), "w") as source_ip_log_file:
            for line in log_file:
                match = re.search(r"SRC={}".format(source_ip), line)

                if match:
                    source_ip_log_file.write(line)


if __name__ == "__main__":
    import sys

    try:
        log_file_path = get_log_file_path(1)

        # Step 5: Investigate the Gateway Firewall Log
        filter_log_records(log_file_path, "sshd", print_records=True)
        filter_log_records(
            log_file_path, "invalid user", print_records=True, print_summary=True
        )
        filter_log_records(
            log_file_path, "invalid user.*220.195.35.40",
            case_sensitive=False, print_records=True, print_summary=True
        )
        filter_log_records(
            log_file_path, "error", print_records=True, print_summary=True
        )
        filter_log_records(
            log_file_path, "pam", case_sensitive=False, print_records=True
        )

        # Step 8: Create Function that Tallies Traffic by Port
        port_counts = tally_traffic_by_port(log_file_path)

        # Step 10: Generate Destination Port Reports
        for port_number, count in port_counts.items():
            if count >= 100:
                generate_destination_port_report(log_file_path, port_number)

        # Step 11: Create Function that Generates Invalid User Report
        generate_invalid_user_report(log_file_path)

        # Step 12: Create Function that Extracts and Saves Source IP Records
        generate_source_ip_log(log_file_path, "220.195.35.40")

    except Exception as e:
        print("An error occurred:", e)
    
    if __name__ == '__main__':
         main()
