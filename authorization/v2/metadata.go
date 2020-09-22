package v2

import (
	"github.com/pkg/errors"
	"strconv"
)

type metadataIdentifier string

const (
	// before metadata field can be used to ensure a URI is only valid
	// until the Unix time specified in the before field
	before metadataIdentifier = "before"
)

func (a *authorizer) validateMetadata(identifier metadataIdentifier, metadata string) (bool, error) {
	switch identifier {
	case before:
		return a.beforeHandler(metadata)
	default:
		return false, errors.New("unknown metadata identifier")
	}
}

func (a *authorizer) beforeHandler(timestampStr string) (bool, error) {
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false, errors.Wrap(err, "could not parse provided timestamp")
	}

	return a.timeProvider.Now().Unix() > timestamp, nil
}
