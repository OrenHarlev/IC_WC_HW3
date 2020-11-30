#!/usr/bin/python3
import os
import click
import datetime
import ipaddress
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

DirectionToNum = { "in" : 1, "out" : 2, "any" : 3 }
NumToDirection = { 1 : "in", 2 : "out", 3 : "any" }

#consts
RuleArgs = 11

def ConvertToAny(ip):
	ipAddr = ipaddress.ip_network(ip, False)
	if int(ipAddr.network_address) == 0 or ipAddr.prefixlen == 0:
		return "any"
	return ip


def RuleRawToPrint(rule):
	rule = rule.split()
	rule[1] = NumToDirection[int(rule[1])]
	rule[2] = ConvertToAny(rule[2])
	rule[3] = ConvertToAny(rule[3])
	rule[4] = NumToProt[int(rule[4])]
	rule[7] = NumToAck[int(rule[7])]
	rule[8] = NumToAction[int(rule[8])]
	return rule


def ReadRules():
    with open(RulesPath, 'r') as f:
        rules = f.read()
    output = Texttable(0)
    output.add_row(["Name", "Direction", "Drc Ip", "Dst Ip", "Protocol", "Src Port", "Dst Port", "Ack", "Action"])
    for rule in rules.splitlines():
        output.add_row(RuleRawToPrint(rule))
    print(output.draw())


def ParseIp(ip):
	ip = ip.lower()
	if ip == "any":
		return "0", "0"
	ipAddr = ipaddress.ip_network(ip, False)
	return str(int(ipAddr.network_address)), str(ipAddr.prefixlen)


def ParsePort(port):
	if port == "any":
		return "0"
	if port == ">1023":
		return "1023"
	return int(port)


def ParseRule(rule):
	rule = rule.split()
	res = []
	res.append(rule[0][:20])
	res.append(DirectionToNum[rule[1].lower()])
	res.extend(ParseIp(rule[2]))
	res.extend(parse_ip(rule[3]))
	res.append(ProtToNum[rule[4].lower()])
	res.append(ParsePort(rule[5]))
	res.append(ParsePort(rule[6]))
	res.append(AckToNum[rule[7].lower()])
	res.append(ActionToNum[rule[8].lower()])
	return " ".join([str(i) for i in res]) + '\n'


def LoadRules(rulesFile):
	rules = rulesFile.read()
	with open(RulesPath, 'w') as f:
		parsedRules = ""
		for rule in rules.splitlines():
			parsedRules += ParseRule(rule)
		if parsedRules[-1] == '\n':
			parsedRules = parsedRules[:-1]
		f.write(parsedRules)


def LogRawToPrint(log):
    log = log.split()
    log[0] =  datetime.datetime.fromtimestamp(int(log[0]) / 1e9).strftime("%d/%m/%Y, %H:%M:%S")
    log[5] = NumToProt[int(log[5])]
    log[6] = NumToAction[int(log[6])]
    log[7] = NumToReason[int(log[7])]


def ReadLog():
    with open(LogReadPath, 'r') as f:
        logs = f.read()
    output = Texttable(0)
    output.add_row(["Timestamp", "Src Ip", "Dst Ip", "Src Port", "Dst Port", "Protocol", "Action", "Reason", "Count"])
    for log in logs.splitlines():
        output.add_row(LogRawToPrint(log))
    print(output.draw())


def ResetLog():
    with open(LogResetPath, 'w') as f:
        f.write("reset")




@click.command()
@click.argument('command', required=True, type=click.Choice(["show_rules", "load_rules", "show_log", "clear_log"]))
@click.argument('rulesfile', required=False, type=click.File('r'))
def main(command, rulesfile):
    if command == "show_rules":
        ReadRules()
    elif command == "load_rules":
        LoadRules(rulesfile)
    elif command == "show_log":
        ReadLog()
    elif command == "clear_log":
        ResetLog()


if __name__ == "__main__":
    main()