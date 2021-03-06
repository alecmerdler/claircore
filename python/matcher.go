package python

import (
	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/pep440"
)

var (
	_ driver.Matcher       = (*Matcher)(nil)
	_ driver.VersionFilter = (*Matcher)(nil)
)

// Matcher attempts to correlate discovered python packages with reported
// vulnerabilities.
type Matcher struct{}

// Name implements driver.Matcher.
func (*Matcher) Name() string { return "python" }

// Filter implements driver.Matcher.
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Package.NormalizedVersion.Kind == "pep440"
}

// Query implements driver.Matcher.
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{}
}

// Vulnerable implements driver.Matcher.
func (*Matcher) Vulnerable(record *claircore.IndexRecord, vuln *claircore.Vulnerability) bool {
	if vuln.Range != nil && record.Package.NormalizedVersion.Kind != "" {
		return vuln.Range.Contains(&record.Package.NormalizedVersion)
	}

	pkg, err := pep440.Parse(record.Package.Version)
	if err != nil {
		return false
	}
	fixed, err := pep440.Parse(vuln.FixedInVersion)
	if err != nil {
		return false
	}
	// pkg < fixed
	return pkg.Compare(&fixed) == -1
}

// VersionFilter opts in to filtering versions in the database.
func (*Matcher) VersionFilter() {}

// VersionAuthoritative implements driver.VersionFilter.
func (*Matcher) VersionAuthoritative() bool { return true }
