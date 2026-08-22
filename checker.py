"""
checker.py
-----------
Deterministic rule engine for NetSage AI.

This module never guesses. It only flags a fault when it can find hard
evidence in the show-command text (or the topology note) using plain
pattern matching and simple math (subnet checks, number comparisons).

If nothing here matches, the case is handed off to the AI prompt engine
(see engine.py) instead of being force-fit into a rule.
"""

import re
import ipaddress
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RuleResult:
    status: str                    # "ERRORS_DETECTED" or "NO_DETERMINISTIC_MATCH"
    root_cause: Optional[str] = None
    evidence: Optional[str] = None
    next_command: Optional[str] = None
    fix_steps: list = field(default_factory=list)
    rule_name: Optional[str] = None


def _nums(pattern, text):
    """Return every number captured by `pattern` in `text`, as a list of ints."""
    return [int(x) for x in re.findall(pattern, text)]


def _iface(text, default="the interface"):
    """Extract a clean interface name after 'interface', dropping any trailing punctuation."""
    m = re.search(r"interface\s+(\S+)", text, re.I)
    return m.group(1).rstrip(";,.") if m else default


def check_case(show_outputs: str, topology_note: str = "", symptom: str = "") -> RuleResult:
    """
    Run every deterministic rule against one case's show-command output.
    Returns the first rule that fires. Order matters: more specific
    checks run before generic ones.
    """
    text = show_outputs or ""
    topo = topology_note or ""
    combined = f"{text} {topo}"

    # 1. Interface / sub-interface administratively down
    if re.search(r"administratively down", text, re.I):
        iface = re.search(r"(GigabitEthernet|FastEthernet|Serial|Vlan)\S*", text)
        iface_name = iface.group(0) if iface else "the interface"
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause=f"{iface_name} is administratively down",
            evidence=text.strip(),
            next_command=f"interface {iface_name}",
            fix_steps=["configure terminal", f"interface {iface_name}", "no shutdown"],
            rule_name="ADMIN_DOWN",
        )

    # 2. Interface manually shut down (e.g. management SVI)
    if re.search(r"\bshutdown\b", text, re.I) and "administratively down" not in text.lower():
        iface = re.search(r"interface (\S+?);?\s", text, re.I)
        iface_name = iface.group(1) if iface else "the interface"
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause=f"{iface_name} is configured with the shutdown command",
            evidence=text.strip(),
            next_command=f"interface {iface_name}",
            fix_steps=["configure terminal", f"interface {iface_name}", "no shutdown"],
            rule_name="MANUAL_SHUTDOWN",
        )

    # 3. DHCP pool exhaustion
    total = re.search(r"total addresses\s+(\d+)", text, re.I)
    leased = re.search(r"leased\s+(\d+)", text, re.I)
    if (total and leased and total.group(1) == leased.group(1)) or re.search(r"zero available", text, re.I):
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause="DHCP pool is fully exhausted (no free addresses left)",
            evidence=text.strip(),
            next_command="show ip dhcp pool",
            fix_steps=["configure terminal", "ip dhcp pool <name>", "network <larger range> <mask>"],
            rule_name="DHCP_EXHAUSTED",
        )

    # 4. DNS lookup disabled on client's gateway
    if re.search(r"no ip domain-lookup", text, re.I):
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause="DNS lookup is disabled on the gateway device",
            evidence=text.strip(),
            next_command="ip domain-lookup",
            fix_steps=["configure terminal", "ip domain-lookup", f"ip name-server <dns-ip>"],
            rule_name="DNS_LOOKUP_DISABLED",
        )

    # 5. OSPF hello-interval mismatch between two neighbours
    hellos = _nums(r"hello-interval\s+(\d+)", text)
    if len(hellos) >= 2 and len(set(hellos)) > 1:
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause=f"OSPF hello-interval mismatch between neighbours ({hellos[0]}s vs {hellos[1]}s)",
            evidence=text.strip(),
            next_command="show ip ospf interface",
            fix_steps=["configure terminal", "interface <if>", f"ip ospf hello-interval {hellos[0]}"],
            rule_name="OSPF_HELLO_MISMATCH",
        )

    # 6. ACL explicitly denying a well-known port (HTTP=80 etc.)
    deny = re.search(r"deny\s+tcp\s+.*?eq\s+(\d+)", text, re.I)
    if deny:
        port = deny.group(1)
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause=f"Extended ACL explicitly blocks TCP port {port}",
            evidence=text.strip(),
            next_command="show access-lists",
            fix_steps=["configure terminal", "no access-list <num> deny tcp ... eq " + port,
                       "access-list <num> permit tcp ... eq " + port],
            rule_name="ACL_DENY_PORT",
        )

    # 7. NAT overload keyword missing
    if re.search(r"ip nat inside source list \d+ interface \S+", text, re.I) and "overload" not in text.lower():
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause="NAT is configured without the 'overload' (PAT) keyword",
            evidence=text.strip(),
            next_command="show ip nat translations",
            fix_steps=["configure terminal", "ip nat inside source list <acl> interface <if> overload"],
            rule_name="NAT_OVERLOAD_MISSING",
        )

    # 8. Static NAT missing "ip nat inside" on the internal interface
    if re.search(r"ip nat inside source static", text, re.I) and re.search(r"missing ip nat inside", text, re.I):
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause="Internal interface is missing the 'ip nat inside' direction command",
            evidence=text.strip(),
            next_command="show ip nat statistics",
            fix_steps=["configure terminal", "interface <internal-if>", "ip nat inside"],
            rule_name="NAT_DIRECTION_MISSING",
        )

    # 9. Overly broad ACL permit ("permit ip ... any")
    if re.search(r"permit ip \S+ [\d.]+ any", text, re.I):
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause="ACL permits this subnet to reach ANY destination — too broad for a guest/isolated VLAN",
            evidence=text.strip(),
            next_command="show access-lists",
            fix_steps=["configure terminal", "no access-list <name>",
                       "access-list <name> deny ip <subnet> <wildcard> <internal-range>",
                       "access-list <name> permit ip <subnet> <wildcard> any"],
            rule_name="ACL_TOO_PERMISSIVE",
        )

    # 10. VLAN missing from a trunk's allowed list
    trunk = re.search(r"switchport trunk allowed vlan ([\d\s]+)", text, re.I)
    vlan_in_symptom = re.search(r"VLAN\s+(\d+)", symptom, re.I)
    if trunk and vlan_in_symptom:
        allowed = [int(v) for v in trunk.group(1).split()]
        needed = int(vlan_in_symptom.group(1))
        if needed not in allowed:
            return RuleResult(
                "ERRORS_DETECTED",
                root_cause=f"VLAN {needed} is missing from the trunk's allowed VLAN list ({allowed})",
                evidence=text.strip(),
                next_command="show interfaces trunk",
                fix_steps=["configure terminal", "interface <trunk-if>",
                           f"switchport trunk allowed vlan add {needed}"],
                rule_name="TRUNK_VLAN_MISSING",
            )

    # 11. Inter-switch link left as access instead of trunk
    if text.lower().count("switchport mode access") >= 2 and re.search(r"across switch", symptom, re.I):
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause="Inter-switch link is configured as access mode instead of trunk",
            evidence=text.strip(),
            next_command="show interfaces switchport",
            fix_steps=["configure terminal", "interface <link>", "switchport mode trunk"],
            rule_name="ACCESS_INSTEAD_OF_TRUNK",
        )

    # 12. Passive-interface enabled on the link that should be forming an OSPF neighbour
    passive = re.search(r"passive-interface\s+(\S+)", text, re.I)
    if passive and passive.group(1) in topo:
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause=f"{passive.group(1)} is set passive, so it cannot form an OSPF neighbour on that link",
            evidence=text.strip(),
            next_command="show ip ospf neighbor",
            fix_steps=["configure terminal", "router ospf 1", f"no passive-interface {passive.group(1)}"],
            rule_name="OSPF_PASSIVE_INTERFACE",
        )

    # 13. Access port assigned to the wrong VLAN
    access_vlan = re.search(r"switchport access vlan\s+(\d+)", text, re.I)
    if access_vlan and vlan_in_symptom:
        configured = int(access_vlan.group(1))
        needed = int(vlan_in_symptom.group(1))
        if configured != needed:
            return RuleResult(
                "ERRORS_DETECTED",
                root_cause=f"Port is assigned to VLAN {configured} instead of the required VLAN {needed}",
                evidence=text.strip(),
                next_command="show interfaces switchport",
                fix_steps=["configure terminal", "interface <port>", f"switchport access vlan {needed}"],
                rule_name="WRONG_ACCESS_VLAN",
            )

    # 14. Missing ip helper-address for DHCP relay
    if re.search(r"missing ip helper-address", text, re.I):
        iface_name = _iface(text)
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause="DHCP relay (ip helper-address) is missing on the client-facing interface",
            evidence=text.strip(),
            next_command=f"interface {iface_name}",
            fix_steps=["configure terminal", f"interface {iface_name}", "ip helper-address <dhcp-server-ip>"],
            rule_name="DHCP_HELPER_MISSING",
        )

    # 15. Static route pointing to an unreachable next-hop
    if re.search(r"next-hop ip [\d.]+ unreachable", text, re.I):
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause="Static route points to a next-hop IP that is unreachable",
            evidence=text.strip(),
            next_command="show ip route",
            fix_steps=["configure terminal", "no ip route <net> <mask> <bad-next-hop>",
                       "ip route <net> <mask> <correct-next-hop>"],
            rule_name="BAD_STATIC_ROUTE",
        )

    # 16. ACL missing a required control port (e.g. FTP control port 21)
    if re.search(r"missing port \d+", text, re.I):
        missing_port = re.search(r"missing port (\d+)", text, re.I).group(1)
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause=f"ACL is missing a permit rule for required port {missing_port}",
            evidence=text.strip(),
            next_command="show access-lists",
            fix_steps=["configure terminal", f"access-list <num> permit tcp any host <server> eq {missing_port}"],
            rule_name="ACL_MISSING_PORT",
        )

    # 17. Native VLAN mismatch on a trunk
    natives = _nums(r"native vlan\s+(\d+)", text)
    if len(natives) >= 2 and len(set(natives)) > 1:
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause=f"Native VLAN mismatch on the trunk ({natives[0]} vs {natives[1]})",
            evidence=text.strip(),
            next_command="show interfaces trunk",
            fix_steps=["configure terminal", "interface <trunk-if>", f"switchport trunk native vlan {natives[0]}"],
            rule_name="NATIVE_VLAN_MISMATCH",
        )

    # 18. Default gateway outside the client's own subnet
    ip_mask = re.search(r"IP\s+([\d.]+)\s+mask\s+([\d.]+).*?Gateway\s+([\d.]+)", text, re.I)
    if ip_mask:
        try:
            iface = ipaddress.ip_interface(f"{ip_mask.group(1)}/{ip_mask.group(2)}")
            gw = ipaddress.ip_address(ip_mask.group(3))
            if gw not in iface.network:
                return RuleResult(
                    "ERRORS_DETECTED",
                    root_cause=f"Default gateway {gw} is outside the host's own subnet {iface.network}",
                    evidence=text.strip(),
                    next_command="show ip interface brief",
                    fix_steps=["Correct the host's default gateway to an address inside " + str(iface.network)],
                    rule_name="GATEWAY_OUTSIDE_SUBNET",
                )
        except ValueError:
            pass

    # 19. Duplicate IP address log
    if re.search(r"DUP_ADDR", text, re.I):
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause="Two hosts are statically configured with the same IP address",
            evidence=text.strip(),
            next_command="show ip arp",
            fix_steps=["Re-address one of the two conflicting hosts to a free IP in the subnet"],
            rule_name="DUPLICATE_IP",
        )

    # 20. VTP domain name case mismatch
    domains = re.findall(r"vtp domain\s+(\S+)", text, re.I)
    if len(domains) >= 2 and domains[0] != domains[1] and domains[0].lower() == domains[1].lower():
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause=f"VTP domain name is case-mismatched between switches ('{domains[0]}' vs '{domains[1]}')",
            evidence=text.strip(),
            next_command="show vtp status",
            fix_steps=["configure terminal", f"vtp domain {domains[0]}"],
            rule_name="VTP_DOMAIN_MISMATCH",
        )

    # 21. DAI trust missing on an uplink
    if re.search(r"ip arp inspection trust missing", text, re.I):
        iface_name = _iface(text, default="the uplink")
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause=f"{iface_name} is not trusted for Dynamic ARP Inspection, so legitimate uplink traffic is dropped",
            evidence=text.strip(),
            next_command=f"interface {iface_name}",
            fix_steps=["configure terminal", f"interface {iface_name}", "ip arp inspection trust"],
            rule_name="DAI_TRUST_MISSING",
        )

    # 22. Port security violation
    if re.search(r"PSECURE_VIOLATION", text, re.I):
        iface = re.search(r"port (\S+)", text, re.I)
        iface_name = iface.group(1) if iface else "the port"
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause=f"Port security violation put {iface_name} into err-disabled state",
            evidence=text.strip(),
            next_command=f"show interfaces {iface_name} status",
            fix_steps=["configure terminal", f"interface {iface_name}", "shutdown", "no shutdown"],
            rule_name="PORT_SECURITY_VIOLATION",
        )

    # 23. HSRP timer mismatch
    hsrp_hellos = _nums(r"standby \d+ priority \d+ hello\s+(\d+)", text)
    if len(hsrp_hellos) >= 2 and len(set(hsrp_hellos)) > 1:
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause=f"HSRP hello timer mismatch between peers ({hsrp_hellos[0]}s vs {hsrp_hellos[1]}s)",
            evidence=text.strip(),
            next_command="show standby brief",
            fix_steps=["configure terminal", "interface <if>", f"standby 1 timers {hsrp_hellos[0]} <hold-time>"],
            rule_name="HSRP_TIMER_MISMATCH",
        )

    # 24. Missing 802.1Q encapsulation on a sub-interface
    if re.search(r"missing encapsulation dot1Q", text, re.I):
        iface_name = _iface(text, default="the sub-interface")
        vlan_num = re.search(r"\.(\d+)\b", iface_name)
        vlan_id = vlan_num.group(1) if vlan_num else "<vlan>"
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause=f"{iface_name} is missing 'encapsulation dot1Q {vlan_id}'",
            evidence=text.strip(),
            next_command=f"interface {iface_name}",
            fix_steps=["configure terminal", f"interface {iface_name}", f"encapsulation dot1Q {vlan_id}"],
            rule_name="MISSING_DOT1Q",
        )

    # 25. IPv6 Router Advertisements suppressed (breaks SLAAC)
    if re.search(r"ipv6 nd suppress-ra", text, re.I):
        iface_name = _iface(text)
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause="IPv6 Router Advertisements are suppressed, so SLAAC clients get no prefix",
            evidence=text.strip(),
            next_command=f"interface {iface_name}",
            fix_steps=["configure terminal", f"interface {iface_name}", "no ipv6 nd suppress-ra"],
            rule_name="IPV6_RA_SUPPRESSED",
        )

    # 26. CDP disabled globally
    if re.search(r"no cdp run", text, re.I):
        return RuleResult(
            "ERRORS_DETECTED",
            root_cause="CDP is disabled globally on the device",
            evidence=text.strip(),
            next_command="show cdp",
            fix_steps=["configure terminal", "cdp run"],
            rule_name="CDP_DISABLED",
        )

    # Nothing matched a hard rule — hand off to the AI prompt engine
    return RuleResult("NO_DETERMINISTIC_MATCH")


if __name__ == "__main__":
    # Quick self-test against the bundled dataset
    import csv
    from pathlib import Path

    path = Path(__file__).resolve().parent / "cases.csv"
    matched, total = 0, 0
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            total += 1
            result = check_case(row["show_outputs"], row["topology_note"], row["symptom"])
            hit = "✅" if result.status == "ERRORS_DETECTED" else "➡️  (to AI)"
            if result.status == "ERRORS_DETECTED":
                matched += 1
            print(f"{row['case_id']:8s} {hit:12s} expected: {row['expected_fault']}")
            if result.status == "ERRORS_DETECTED":
                print(f"         rule matched: {result.root_cause}")
    print(f"\n{matched}/{total} cases resolved deterministically; "
          f"{total - matched} handed off to the AI prompt engine.")
