package pgo

import (
	"testing"
)

func TestFindEachKeywords(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		keywords []string
		want     []string
		wantErr  bool
	}{
		{
			name:     "normal case - some matches",
			source:   "hello world, welcome to Go",
			keywords: []string{"world", "mars", "Go", "rust"},
			want:     []string{"world", "Go"},
			wantErr:  false,
		},
		{
			name:     "no matches",
			source:   "hello universe",
			keywords: []string{"mars", "jupiter"},
			want:     []string{},
			wantErr:  false,
		},
		{
			name:     "empty source",
			source:   "",
			keywords: []string{"test"},
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "empty keywords",
			source:   "hello",
			keywords: []string{},
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "both empty",
			source:   "",
			keywords: []string{},
			want:     nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FindEachKeywords(tt.source, tt.keywords)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindEachKeywords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !equalStringSlice(got, tt.want) {
				t.Errorf("FindEachKeywords() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindAndReplaceAll(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		query   string
		repl    string
		want    string
		wantErr bool
	}{
		{
			name:    "normal replace",
			source:  "hello world world",
			query:   "world",
			repl:    "Go",
			want:    "hello Go Go",
			wantErr: false,
		},
		{
			name:    "no match",
			source:  "hello universe",
			query:   "mars",
			repl:    "planet",
			want:    "hello universe",
			wantErr: false,
		},
		{
			name:    "empty source",
			source:  "",
			query:   "x",
			repl:    "y",
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty query",
			source:  "hello",
			query:   "",
			repl:    "x",
			want:    "hello",
			wantErr: true,
		},
		{
			name:    "replace with empty",
			source:  "abc123def",
			query:   "123",
			repl:    "",
			want:    "abcdef",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FindAndReplaceAll(tt.source, tt.query, tt.repl)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindAndReplaceAll() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("FindAndReplaceAll() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindInputEndWith(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		search string
		want   bool
	}{
		{"ends with match", "file.txt", ".txt", true},
		{"no match", "image.png", ".jpg", false},
		{"exact match", "go", "go", true},
		{"empty input", "", "x", false},
		{"empty search", "hello", "", false},
		{"both empty", "", "", false},
		{"search longer than input", "hi", "hello", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FindInputEndWith(tt.input, tt.search); got != tt.want {
				t.Errorf("FindInputEndWith() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindInputStartWith(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		search string
		want   bool
	}{
		{"starts with match", "https://example.com", "https://", true},
		{"no match", "http://example.com", "https://", false},
		{"exact match", "go", "go", true},
		{"empty input", "", "x", false},
		{"empty search", "hello", "", false},
		{"both empty", "", "", false},
		{"search longer than input", "hi", "hello", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FindInputStartWith(tt.input, tt.search); got != tt.want {
				t.Errorf("FindInputStartWith() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindAndExtractKeywordAfter(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		keyword string
		want    string
		wantErr bool
	}{
		{"found", "name=JohnDoe", "=", "JohnDoe", false},
		{"at beginning", "prefixsuffix", "prefix", "suffix", false},
		{"at end", "hello=", "=", "", false},
		{"not found", "hello world", "@", "", true},
		{"empty source", "", "x", "", true},
		{"empty keyword", "hello", "", "hello", false}, // note: Index("", "") == 0
		{"keyword same as source", "test", "test", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FindAndExtractKeywordAfter(tt.source, tt.keyword)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindAndExtractKeywordAfter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("FindAndExtractKeywordAfter() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindAndExtractKeywordBefore(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		keyword string
		want    string
		wantErr bool
	}{
		{"found", "JohnDoe@email.com", "@", "JohnDoe", false},
		{"at beginning", "prefixsuffix", "prefix", "", false},
		{"at end", "hello=", "=", "hello", false},
		{"not found", "hello world", "@", "", true},
		{"empty source", "", "x", "", true},
		{"empty keyword", "hello", "", "", false}, // Index("hello", "") == 0 → before = ""
		{"keyword same as source", "test", "test", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FindAndExtractKeywordBefore(tt.source, tt.keyword)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindAndExtractKeywordBefore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("FindAndExtractKeywordBefore() = %q, want %q", got, tt.want)
			}
		})
	}
}

// helper function to compare two string slices for equality
func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
