package profiles

import "testing"

func TestProfileTimeoutsCoverEverySupportedTool(t *testing.T) {
	for _, profileName := range Names() {
		p, err := Get(profileName)
		if err != nil {
			t.Fatal(err)
		}
		for _, tool := range SupportedTools() {
			timeout, ok := p.TimeoutFor(tool)
			if !ok {
				t.Fatalf("%s missing timeout for %s", profileName, tool)
			}
			if timeout <= 0 {
				t.Fatalf("%s timeout for %s must be positive", profileName, tool)
			}
		}
	}
}

func TestProfileDepthIncreasesTimeouts(t *testing.T) {
	fast, _ := Get(Fast)
	normal, _ := Get(Normal)
	deep, _ := Get(Deep)
	for _, tool := range SupportedTools() {
		ft, _ := fast.TimeoutFor(tool)
		nt, _ := normal.TimeoutFor(tool)
		dt, _ := deep.TimeoutFor(tool)
		if !(ft <= nt && nt <= dt) {
			t.Fatalf("%s not ordered fast=%s normal=%s deep=%s", tool, ft, nt, dt)
		}
	}
}
