package rules

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/djeeteg007/tf-why/internal/plan"
)

var sgTypes = map[string]bool{
	"aws_security_group_rule": true,
	"aws_security_group":      true,
}

// Dangerous inbound ports when exposed to 0.0.0.0/0 or ::/0.
var dangerousPorts = map[int]string{
	22:   "SSH",
	3389: "RDP",
	5432: "PostgreSQL",
	3306: "MySQL",
	9200: "Elasticsearch",
	6379: "Redis",
}

// SecurityGroupRule detects overly permissive security group configurations.
type SecurityGroupRule struct{}

func (r *SecurityGroupRule) Evaluate(rc plan.ResourceChange) []RuleFinding {
	if !sgTypes[rc.Type] {
		return nil
	}

	action := rc.Change.Actions.ActionType()
	if action == plan.ActionNoop || action == plan.ActionRead || action == plan.ActionDelete {
		return nil
	}

	afterData := getAfterState(rc)
	if afterData == nil {
		return nil
	}

	if rc.Type == "aws_security_group_rule" {
		return r.evaluateRule(afterData, rc)
	}

	return r.evaluateSecurityGroup(afterData, rc)
}

func (r *SecurityGroupRule) evaluateRule(data map[string]interface{}, rc plan.ResourceChange) []RuleFinding {
	// Only check ingress rules.
	ruleType, _ := data["type"].(string)
	if ruleType != "ingress" {
		return nil
	}

	cidrs := extractCIDRs(data)
	if !hasOpenCIDR(cidrs) {
		return nil
	}

	fromPort := intFromJSON(data["from_port"])
	toPort := intFromJSON(data["to_port"])
	protocol, _ := data["protocol"].(string)

	return checkPorts(fromPort, toPort, protocol, cidrs, rc.Address)
}

func (r *SecurityGroupRule) evaluateSecurityGroup(data map[string]interface{}, rc plan.ResourceChange) []RuleFinding {
	// Check inline ingress rules.
	ingressRaw, ok := data["ingress"]
	if !ok {
		return nil
	}

	ingressList, ok := ingressRaw.([]interface{})
	if !ok {
		return nil
	}

	var findings []RuleFinding
	for _, item := range ingressList {
		rule, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		cidrs := extractCIDRsFromInline(rule)
		if !hasOpenCIDR(cidrs) {
			continue
		}

		fromPort := intFromJSON(rule["from_port"])
		toPort := intFromJSON(rule["to_port"])
		protocol, _ := rule["protocol"].(string)

		findings = append(findings, checkPorts(fromPort, toPort, protocol, cidrs, rc.Address)...)
	}

	return findings
}

func checkPorts(fromPort, toPort int, protocol string, cidrs []string, address string) []RuleFinding {
	// If protocol is -1 (all), all ports are open.
	allPorts := protocol == "-1" || protocol == "all"

	var findings []RuleFinding
	openCIDRs := filterOpenCIDRs(cidrs)
	cidrStr := strings.Join(openCIDRs, ", ")

	for port, svcName := range dangerousPorts {
		if allPorts || (port >= fromPort && port <= toPort) {
			findings = append(findings, RuleFinding{
				Severity: SeverityHigh,
				Tags:     []string{"security"},
				Title:    fmt.Sprintf("%s port %d (%s) open to the internet on %s", svcName, port, protocol, address),
				Address:  address,
				Why: []string{
					fmt.Sprintf("CIDR %s allows inbound traffic on port %d (%s)", cidrStr, port, svcName),
					fmt.Sprintf("Protocol: %s, Port range: %d-%d", protocol, fromPort, toPort),
				},
				Recommendations: []string{
					fmt.Sprintf("Restrict CIDR to specific IP ranges instead of %s", cidrStr),
					fmt.Sprintf("Use a bastion host or VPN for %s access", svcName),
				},
			})
		}
	}

	return findings
}

func extractCIDRs(data map[string]interface{}) []string {
	var cidrs []string
	for _, key := range []string{"cidr_blocks", "ipv6_cidr_blocks"} {
		if raw, ok := data[key]; ok {
			if list, ok := raw.([]interface{}); ok {
				for _, item := range list {
					if s, ok := item.(string); ok {
						cidrs = append(cidrs, s)
					}
				}
			}
		}
	}
	return cidrs
}

func extractCIDRsFromInline(rule map[string]interface{}) []string {
	var cidrs []string
	for _, key := range []string{"cidr_blocks", "ipv6_cidr_blocks"} {
		if raw, ok := rule[key]; ok {
			if list, ok := raw.([]interface{}); ok {
				for _, item := range list {
					if s, ok := item.(string); ok {
						cidrs = append(cidrs, s)
					}
				}
			}
		}
	}
	return cidrs
}

func hasOpenCIDR(cidrs []string) bool {
	for _, c := range cidrs {
		if c == "0.0.0.0/0" || c == "::/0" {
			return true
		}
	}
	return false
}

func filterOpenCIDRs(cidrs []string) []string {
	var result []string
	for _, c := range cidrs {
		if c == "0.0.0.0/0" || c == "::/0" {
			result = append(result, c)
		}
	}
	return result
}

func intFromJSON(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case json.Number:
		i, _ := val.Int64()
		return int(i)
	case int:
		return val
	}
	return 0
}
