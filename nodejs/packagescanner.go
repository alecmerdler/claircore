package nodejs

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/rs/zerolog"
)

var (
	_ indexer.VersionedScanner = (*Scanner)(nil)
	_ indexer.PackageScanner   = (*Scanner)(nil)
)

// Scanner implements the scanner.PackageScanner interface.
//
// It looks for directories that seem like wheels or eggs, and looks at the
// metadata recorded there.
//
// The zero value is ready to use.
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return "nodejs" }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return "0.0.1" }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return "package" }

// Scan attempts to find `package.json` directories and record the package
// information there.
//
// A return of (nil, nil) is expected if there's nothing found.
func (ps *Scanner) Scan(ctx context.Context, layer *claircore.Layer) ([]*claircore.Package, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", layer.Hash.String())
	log := zerolog.Ctx(ctx).With().
		Str("component", "nodejs/Scanner.Scan").
		Str("version", ps.Version()).
		Str("layer", layer.Hash.String()).
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r, err := layer.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	rd, ok := r.(interface {
		io.ReadCloser
		io.Seeker
	})
	if !ok {
		return nil, errors.New("nodejs: cannot seek on returned layer Reader")
	}

	var ret []*claircore.Package
	tr := tar.NewReader(rd)
	var h *tar.Header
	for h, err = tr.Next(); err == nil; h, err = tr.Next() {
		n, err := filepath.Rel("/", filepath.Join("/", h.Name))
		if err != nil {
			return nil, err
		}
		switch {
		case h.Typeflag != tar.TypeReg:
			// Should we chase symlinks with the correct name?
			continue
		case strings.HasSuffix(n, `package.json`):
			log.Debug().Str("file", n).Msg("found package.json")
		default:
			continue
		}

		packageJSONFile, err := ioutil.ReadFile(n)
		if err != nil {
			log.Debug().Str("file", n).Msg("could not read file")
			continue
		}
		var packageJSON map[string]interface{}
		err = json.Unmarshal(packageJSONFile, &packageJSON)
		if err != nil {
			log.Debug().Str("file", n).Msg("could not unmarshal into JSON")
			continue
		}

		for packageName, semver := range packageJSON["dependencies"].(map[string]string) {
			ret = append(ret, &claircore.Package{
				Name:      packageName,
				Version:   semver,
				PackageDB: "nodejs:" + n,
				Kind:      "source",
				// FIXME(alecmerdler): What to put here
				NormalizedVersion: claircore.Version{},
				RepositoryHint:    "http://registry.npmjs.com/" + packageName,
			})
		}
	}
	if err != io.EOF {
		return nil, err
	}
	return ret, nil
}
