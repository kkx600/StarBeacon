package store

import "testing"

func TestBypassRuleActionsRequireIndependentCapability(t *testing.T) {
	for _, text := range []string{"# comment only", "drop tcp any any -> any any (sid:1000001;)", "alert tcp any any -> any any ( LUA :evil.lua; sid:1000001;)", "alert tcp any any -> any any ( bypass ; sid:1000001;)", "alert tcp any any -> any any (dataset:set,x;sid:1000001;)"} {
		if ValidateRules(text) == nil {
			t.Fatal("超出旁路规则边界的内容被接受", text)
		}
	}
	if err := ValidateRules("# detection\nalert tcp any any -> any any (content:\"test\";sid:1000001;rev:1;)\n"); err != nil {
		t.Fatal(err)
	}
}
