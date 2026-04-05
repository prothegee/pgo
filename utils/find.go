package pgo

import (
	"fmt"
	"strings"
)

// find each keywords from `k` in source `s`
//
// params:
//
//	s string - source
//	k []string - keywords you want to search
//
// return: []string, error - result, err||nil
func FindEachKeywords(s string, k []string) ([]string, error) {
	var res []string

	if len(s) <= 0 {
		return res, fmt.Errorf("source string is empty")
	}
	if len(k) <= 0 {
		return res, fmt.Errorf("keywords string is empty")
	}

	for _, k := range k {
		if strings.Contains(s, k) {
			res = append(res, k)
		}
	}

	return res, nil
}

// find and replace all `s` from `q` with `r`
//
// params:
//
//	s string - source
//	q string - query
//	r string - replacement
//
// return: string, error - result, err||nil
func FindAndReplaceAll(s, q, r string) (string, error) {
	if s == "" {
		return s, fmt.Errorf("source is empty")
	}
	if q == "" {
		return s, fmt.Errorf("query is empty")
	}
	res := strings.ReplaceAll(s, q, r)
	return res, nil
}

// find input `i` end with search `s`
//
// params:
//
//	i string - input
//	s string - search
//
// return: bool - true if found
func FindInputEndWith(i, s string) bool {
	if len(i) <= 0 || len(s) <= 0 {
		return false
	}
	if len(i) < len(s) {
		return false
	}
	if strings.HasSuffix(i, s) {
		return true
	}
	return false
}

// find input `i` start with search `s`
//
// params:
//
//	i string - input
//	s string - search
//
// return: bool - true if found
func FindInputStartWith(i, s string) bool {
	if len(i) <= 0 || len(s) <= 0 {
		return false
	}
	if len(i) < len(s) {
		return false
	}
	if strings.HasPrefix(i, s) {
		return true
	}
	return false
}

// find and extract source keyword after `k` from source `s`
//
// params:
//
//	s string - source
//	k string - keyword
//
// @return bool - true if found
func FindAndExtractKeywordAfter(s, k string) (string, error) {
	pos := strings.Index(s, k)
	if pos == -1 {
		return "", fmt.Errorf("substring `k` is not in present of `s`")
	}
	return s[pos+len(k):], nil
}

// find and extract source keyword after `k` from source `s`
//
// params:
//
//	s string - source
//	k string - keyword
//
// return: bool - true if found
func FindAndExtractKeywordBefore(s, k string) (string, error) {
	pos := strings.Index(s, k)
	if pos == -1 {
		return "", fmt.Errorf("substring `k` is not in present of `s`")
	}
	return s[:pos], nil
}
