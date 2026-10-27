# Augustine
# Assignment 4 Firewall rules

DEFAULT_ACTION = "DENY"

rules = [
    (443, "ALLOW"),
    (80, "ALLOW"),
    (23, "DENY"),
    (22, "ALLOW"),
    (22, "DENY"),
    (3389, "DENY"),
    (53, "ALLOW"),
]

packets = [
    ("09:00", "10.0.0.5", 443),
    ("09:00", "10.0.0.5", 80),
    ("09:01", "41.0.0.9", 23),
    ("09:01", "10.0.0.7", 22),
    ("09:02", "41.0.0.9", 3389),
    ("09:02", "10.0.0.8", 53),
    ("09:03", "41.0.0.9", 445),
    ("09:03", "10.0.0.5", 443),
    ("09:04", "41.0.0.9", 3389),
    ("09:04", "10.0.0.9", 8080),
    ("09:05", "41.0.0.9", 23),
    ("09:05", "10.0.0.7", 22),
    ("09:06", "41.0.0.9", 3389),
    ("09:06", "10.0.0.8", 53),
    ("09:07", "41.0.0.9", 21),
    ("09:07", "10.0.0.5", 80),
    ]

def find_action(port, rules, default=DEFAULT_ACTION):
    for rule_port, action in rules:
        if rule_port == port:
            return action
        return default
def filter_packets(packets, rules):
    allowed=[]
    denied=[]
    for time, ip, port in packets:
        if find_action(port, rules) == "ALLOW":
            allowed.append((time, ip, port))
        else:
            denied.append((time, ip, port))
    return allowed, denied
def unique_values(packets, positions):
    result = []
    for packets in packets:
        value = packets[positions]
        if value not in result:
            result.append(value)
    return result
def count_matches(packets, positions, value):
    count = 0
    for packets in packets:
        if packets[positions]==value:
            count += 1
    return count
def parcent(part,whole):
    if whole ==0:
        percentage=0
        return 0
    return part/whole*100
for time, ip, port in packets:
    print(time,ip, "->port", port, find_action(port, rules))

print("==total==")
allowed, denied = filter_packets(packets, rules)
print("packets checked", len(packets))
print("allowed", len(allowed))
print("denied",len(denied))
print("denied percentage: " f"{parcent(len(denied), len(packets))}%")

print ("denied ports")
denied_ports = unique_values(denied, 2)
denied_ports.sort()
print(denied_ports)

print("==Ranking of source IPs by denied packets==")
ranking = []
for ip in unique_values(denied, 1):
    ranking.append((count_matches(denied, 1, ip), ip))
ranking.sort(reverse=True)
for count, ip in ranking:
    print(ip, "with", count, "denied")

print("Denied only because no rule matched")
no_rule = []
for port in unique_values(packets, 2):
    if find_action(port, rules, "NONE") == "NONE":
        no_rule.append(port)
print(no_rule)
print("==Function tests==")
print("find_action(22):", find_action(22, rules))
print("find_action(445):", find_action(445, rules))
print("find_action(8080):", find_action(8080, rules))
    
