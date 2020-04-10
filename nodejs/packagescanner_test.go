package nodejs_test

import (
	"context"
	"path"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/nodejs"
	"github.com/quay/claircore/test"
)

// TestScan runs the NodeJS scanner over some layers known to have NodeJS
// packages installed.
func TestScan(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	for _, tc := range scanTable {
		t.Run(path.Base(tc.Name), tc.Run(ctx))
	}
}

var scanTable = []test.ScannerTestcase{
	{
		Domain: "docker.io",
		Name:   "bitnami/express",
		Hash:   "sha256:b1f3cf4a73d18cbd846e41b07fd6f84dff165147d0da333eec97e7af93e29610",
		Want: []*claircore.Package{
			// FIXME(alecmerdler): Change this to expect NodeJS packages...
			{
				Name:           "appdirs",
				Version:        "1.4.3",
				Kind:           "source",
				PackageDB:      "python:usr/local/lib/python3.7/site-packages",
				RepositoryHint: "https://pypi.org/simple",
				NormalizedVersion: claircore.Version{
					Kind: "pep440",
					V:    [...]int32{0, 1, 4, 3, 0, 0, 0, 0, 0, 0},
				},
			},
		},
		Scanner: &nodejs.Scanner{},
	},
}
