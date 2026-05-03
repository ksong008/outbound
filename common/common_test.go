package common

import (
	"bytes"
	"net/url"
	"testing"
)

func TestBytesAddBigEndian(t *testing.T) {
	tt := [][2][]byte{
		{{0, 0, 0}, {0, 0, 1}},
		{{0, 0, 255}, {0, 1, 0}},
		{{0, 255, 255}, {1, 0, 0}},
		{{255, 255, 255}, {0, 0, 0}},
		{{55, 255, 255}, {56, 0, 0}},
		{{56, 23, 255}, {56, 24, 0}},
		{{56, 24, 22}, {56, 24, 23}},
	}
	for i, test := range tt {
		BytesIncBigEndian(test[0])
		if !bytes.Equal(test[0], test[1]) {
			t.Fatal(i, test[0], "!=", test[1])
		}
	}
}

func TestBytesAddLittleEndian(t *testing.T) {
	tt := [][2][]byte{
		{{0, 0, 0}, {1, 0, 0}},
		{{255, 0, 0}, {0, 1, 0}},
		{{255, 255, 0}, {0, 0, 1}},
		{{255, 255, 255}, {0, 0, 0}},
		{{255, 255, 55}, {0, 0, 56}},
		{{255, 23, 56}, {0, 24, 56}},
		{{22, 24, 56}, {23, 24, 56}},
	}
	for i, test := range tt {
		BytesIncLittleEndian(test[0])
		if !bytes.Equal(test[0], test[1]) {
			t.Fatal(i, test[0], "!=", test[1])
		}
	}
}

func TestParseAllowInsecure(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  bool
	}{
		{name: "allowInsecure", query: "allowInsecure=1", want: true},
		{name: "allow_insecure", query: "allow_insecure=true", want: true},
		{name: "allowinsecure", query: "allowinsecure=1", want: true},
		{name: "skipVerify", query: "skipVerify=true", want: true},
		{name: "missing", query: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			values, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatalf("ParseQuery returned error: %v", err)
			}
			if got := ParseAllowInsecure(values); got != tc.want {
				t.Fatalf("ParseAllowInsecure() = %v, want %v", got, tc.want)
			}
		})
	}
}
