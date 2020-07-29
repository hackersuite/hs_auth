package uri

import (
	"errors"
	"strings"
)

var (
	ErrInvalidURI = errors.New("invalid URI string")
)

//hs:<service_name>:<subsystem>:<version>:<category>:<resource_name>?<allowed_arguments>#<permission_metadata>
type URI struct {
	Path      string
	Arguments map[string]string
	Metadata  map[string]string
}

// hs:<service_name>:<subsystem>:<version>:<category>:<resource_name>?<allowed_arguments>#<permission_metadata>
func ParseURI(source string) (*URI, error) {
	var (
		arguments map[string]string = nil
		metadata  map[string]string = nil
	)

	pathArgumentSplit := strings.Split(source, "?")
	path := pathArgumentSplit[0]

	if len(pathArgumentSplit) > 2 {
		return nil, ErrInvalidURI
	}

	if len(pathArgumentSplit) == 2 {
		var err error

		argumentsMetadataSplit := strings.Split(pathArgumentSplit[1], "#")
		arguments, err = UnmarshalArguments(argumentsMetadataSplit[0])
		if err != nil {
			return nil, err
		}

		if len(argumentsMetadataSplit) > 1 {
			metadata, err = UnmarshalMetadata(argumentsMetadataSplit[1])
			if err != nil {
				return nil, err
			}
		}
	}

	return &URI{
		Path:      path,
		Arguments: arguments,
		Metadata:  metadata,
	}, nil
}

func UnmarshalArguments(source string) (map[string]string, error) {
	arguments := strings.Split(source, "&")
	toReturn := map[string]string{}
	for _, arg := range arguments {
		split := strings.Split(arg, "=")
		toReturn[split[0]] = split[1]
	}
	return toReturn, nil
}

func UnmarshalMetadata(source string) (map[string]string, error) {
	arguments := strings.Split(source, "#")
	toReturn := map[string]string{}
	for _, arg := range arguments {
		split := strings.Split(arg, "=")
		toReturn[split[0]] = split[1]
	}
	return toReturn, nil
}
