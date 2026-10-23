package strictjson

import (
	"strings"
	"testing"
)

func TestAmbiguityAndLimits(t *testing.T) {
	type control struct {
		Key int `json:"key"`
	}
	cases := []string{`{"key":1,"key":2}`, `{"Key":1}`, `{"key":1} {}`, `{"key":1,"other":2}`, strings.Repeat("[", 34) + "1" + strings.Repeat("]", 34)}
	for _, s := range cases {
		var c control
		if Decode([]byte(s), 4096, &c) == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
	var c control
	if Decode([]byte(`{"key":1}`), 4, &c) == nil {
		t.Fatal("byte limit bypass")
	}
	if Decode([]byte(`{"key":1}`), 100, &c) != nil || c.Key != 1 {
		t.Fatal("valid JSON refused")
	}
}
func TestInvalidUTF8(t *testing.T) {
	var dst map[string]string
	if Decode([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, 100, &dst) == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}
