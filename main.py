import click
import os

PATH = "/sys/class/FW/FW_TRACER/sysfs_att"
TRACE_FORMAT = "Firewall Packets Summary:\nNumber of accepted packets: {}\nNumber of dropped packets: {}\nTotal number of packets: {}"

def get_logs():
    with open(PATH, 'r') as f:
        fw_output = f.read()
    return [int(x) for x in fw_output.split(" ")]

def print_trace():
    accepted_packets_count, dropped_packets_count = get_logs()
    print(TRACE_FORMAT.format(accepted_packets_count, dropped_packets_count, accepted_packets_count + dropped_packets_count))

def reset_packets_counters():
    with open(PATH, 'w') as f:
        f.write("0")

@click.command()
@click.argument('arg', required=False, type=click.Choice(["0"]))
def main(arg):
    if arg is None:
        print_trace()
    elif arg == "0":
        reset_packets_counters()


if __name__ == "__main__":
    main()