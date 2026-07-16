package output

import (
	"testing"

	"hfinger/config"
)

func resetOutputState() {
	filetype = ""
	filepath = ""
	results = nil
}

func TestSetOutput_BitsUT(t *testing.T) {
	t.Cleanup(resetOutputState)
	resetOutputState()

	tests := []struct {
		name    string
		format  string
		path    string
		wantErr bool
	}{
		{name: "json output", format: "json", path: "result.json"},
		{name: "xml output", format: "xml", path: "result.xml"},
		{name: "xlsx output", format: "xlsx", path: "result.xlsx"},
		{name: "unsupported output", format: "csv", path: "result.csv", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetOutputState()
			err := SetOutput(tt.format, tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("SetOutput() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("SetOutput() unexpected error: %v", err)
			}
			gotType, gotPath := GetOutput()
			if gotType != tt.format || gotPath != tt.path {
				t.Fatalf("GetOutput() = (%q, %q), want (%q, %q)", gotType, gotPath, tt.format, tt.path)
			}
		})
	}
}

func TestAddAndGetResults_BitsUT(t *testing.T) {
	t.Cleanup(resetOutputState)
	resetOutputState()

	first := config.Result{URL: "https://example.com", CMS: "ExampleCMS", StatusCode: 200}
	second := config.Result{URL: "https://example.org", CMS: "OtherCMS", StatusCode: 404}

	AddResults(first)
	AddResults(second)

	got := GetResults()
	if len(got) != 2 {
		t.Fatalf("GetResults() length = %d, want 2", len(got))
	}
	if got[0] != first || got[1] != second {
		t.Fatalf("GetResults() = %#v, want [%#v %#v]", got, first, second)
	}
}
