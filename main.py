#!/usr/bin/python3
import os
import click
import datetime
from texttable import Texttable

#devises paths:
RulesPath = "/sys/class/fw/rules/rules"
LogReadPath = "/dev/fw_log"
LogResetPath = "/sys/class/fw/log/reset"

#log parsing:
NumToAction = { 0 : "drop", 1 : "accept" }
ActionToNum = { "drop" : 0, "accept" : 1 }

NumToProt = { 1 : "icmp", 6 : "tcp", 17 : "udp", 255 : "other", 143 : "any" }
ProtToNum = {"icmp" : 1, "tcp" : 6, "udp" : 17, "other" : 255, "any" : 143 }

NumToReason = { -1 : "REASON_FW_INACTIVE", -2 : "REASON_NO_MATCHING_RULE", -4 : "REASON_XMAS_PACKET", -6 : "REASON_ILLEGAL_VALUE" }
ReasonToNum = { "REASON_FW_INACTIVE" : -1, "REASON_NO_MATCHING_RULE" : -2, "REASON_XMAS_PACKET" : -4, "REASON_ILLEGAL_VALUE" : -6 }

NumToAck = { 1 : "no", 2 : "yes", 3 : "any" }
AckToNum = { "no" : 1, "yes" : 2, "any" : 3 }

NumToDirection = { "in" : 1, "out" : 2, "any" : 3 }
DirectionToNum = { 1 : "in", 2 : "out", 3 : "any" }

def show_rules():
    with open(RulesPath, 'r') as f:
        rules = f.read()
    table = Texttable(0)
    table.add_row(["Name", "Direction", "Src Ip", "Dst Ip", "Protocol", "Src Port", "Dst Port", "Ack", "Action"])
    for rule in rules.splitlines():
        line[1] = int_to_direction[int(line[1])]


def FormatRule(rule):
    rule = rule.split
    result = []
    result[0] = rule[:20]
    result[1]
    rule[1] = DirectionToNum[rule[1]]


def LoadRules(rulesFile):
    rules = rulesFile.read().splitlines()
    for rule in rules:
        rule = formatRule(rule)
    with open(RulesPath. 'w') as f:
        

def show_log():
    with open(SHOWING_LOGS_PATH, 'r') as f:
        logs = f.read()
    t = Texttable(0)
    t.add_row(["Timestamp", , "Src Ip", "Dst Ip", "Src Port", "Dst Port", "Protocol", "Action", "Reason", "Count"])
    for line in logs.splitlines():
        line = line.split()
        line[0] =  datetime.datetime.fromtimestamp(int(line[0]) / 1e9).strftime("%d/%m/%Y, %H:%M:%S")
        line[5] = int_to_protocol[int(line[5])]
        line[6] = int_to_action[int(line[6])]
        line[7] = int_to_reason[int(line[7])]
        t.add_row(line)
    print(t.draw())


def clear_log():
    with open(LogResetPath, 'w') as f:
        f.write("reset")


@click.command()
@click.argument('command', required=True, type=click.Choice(["show_rules", "load_rules", "show_log", "clear_log"]))
@click.argument('rulesFile', required=False, type=click.File('r'))
def main(command, rulesFile):
    if arg == "show_rules":
        show_rules()
    elif arg == "load_rules":
        LoadRules(rulesFile)
    elif arg == "show_log":
        show_log()
    elif arg == "clear_log":
        clear_log()


if __name__ == "__main__":
    main()