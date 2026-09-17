// agent_wan_test.go — #276: the WAN state travels in the agent payload.
// An agent_only router has no SSH client, so the server's probe never runs:
// without the payload field the gateway's connection panel stays at "—" even
// with the uplink perfectly up.
package adapters

import (
	"testing"

	"github.com/gnacho/netpulse/agent/probe"
)

func TestPolledFromAgentTakesWanFromPayload(t *testing.T) {
	l := NewLive(nil, nil, []RouterConfig{
		{ID: "gateway", Host: "192.0.2.1", Name: "openwrt", IsGateway: true, AgentOnly: true},
	}, nil)
	payload := &probe.Payload{
		Router: "gateway", Ts: 1, Version: "2.28.24",
		Data: probe.PayloadData{Wan: &probe.WanInfo{
			Proto: "pppoe", Device: "pppoe-isp", Port: "lan1",
			IP: "203.0.113.45", Gateway: "198.51.100.1",
			DNS: []string{"198.51.100.53"},
		}},
	}
	p := l.polledFromAgent(l.routers[0], payload)
	if p.wanInfo.IP != "203.0.113.45" || p.wanInfo.Proto != "pppoe" {
		t.Fatalf("wanInfo from the payload: %+v", p.wanInfo)
	}
	if p.wanInfo.Gateway != "198.51.100.1" || p.wanInfo.Port != "lan1" {
		t.Fatalf("wanInfo from the payload: %+v", p.wanInfo)
	}
}

func TestPolledFromAgentWithoutWanStaysEmpty(t *testing.T) {
	// An old agent (without the field) or an AP with no uplink: nothing to
	// ingest, and the server can still probe over SSH when the router allows
	// it.
	l := NewLive(nil, nil, []RouterConfig{{ID: "ap1", Host: "192.0.2.2", Name: "ap"}}, nil)
	payload := &probe.Payload{Router: "ap1", Ts: 1, Version: "2.28.0"}
	p := l.polledFromAgent(l.routers[0], payload)
	if p.wanInfo.Proto != "" || p.wanInfo.IP != "" {
		t.Fatalf("no wan in the payload should stay empty: %+v", p.wanInfo)
	}
}
