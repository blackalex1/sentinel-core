package main

import (
	"testing"
)

func TestParseSingleSiteGroup_Empty(t *testing.T) {
	cat := parseSingleSiteGroup([]byte{})
	if cat.Tag != "" {
		t.Fatalf("expected empty tag on empty data, got: %s", cat.Tag)
	}
}

func TestParseSingleGeoIP_Empty(t *testing.T) {
	g := parseSingleGeoIP([]byte{})
	if g.CountryCode != "" {
		t.Fatalf("expected empty country code on empty data, got: %s", g.CountryCode)
	}
}
