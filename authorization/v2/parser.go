package v2

import (
	"strings"
)

// NewURIFromString parses the string representation of a URI into the URI struct.
// NewURIFromString expects the string to be of the following form, otherwise ErrInvalidURI is returned
// hs:<service_name>:<subsystem>:<version>:<category>:<resource_name>?<allowed_arguments>#<permission_metadata>
func NewURIFromString(source string) (UniformResourceIdentifier, error) {
	var (
		arguments map[string]string = nil
		metadata  map[string]string = nil
	)

	pathArgumentSplit := strings.Split(source, "?")
	path := pathArgumentSplit[0]

	if len(pathArgumentSplit) > 2 {
		return UniformResourceIdentifier{}, ErrInvalidURI
	}

	if len(pathArgumentSplit) == 2 {
		var err error

		argumentsMetadataSplit := strings.Split(pathArgumentSplit[1], "#")
		arguments, err = unmarshalArguments(argumentsMetadataSplit[0])
		if err != nil {
			return UniformResourceIdentifier{}, err
		}

		if len(argumentsMetadataSplit) > 1 {
			metadata, err = unmarshalArguments(argumentsMetadataSplit[1])
			if err != nil {
				return UniformResourceIdentifier{}, err
			}
		}
	}

	return UniformResourceIdentifier{
		path:      path,
		arguments: arguments,
		metadata:  metadata,
	}, nil
}

// MarshalJSON will convert the URI structure into the standard string representation for URIs
func (uri UniformResourceIdentifier) MarshalJSON() ([]byte, error) {
	var (
		marshalledURI      = uri.path
		marshalledArgs     = marshallURIMap(uri.arguments)
		marshalledMetadata = marshallURIMap(uri.metadata)
	)

	if len(marshalledArgs) > 0 {
		marshalledURI += "?" + marshalledArgs
	}

	if len(marshalledMetadata) > 0 {
		marshalledURI += "#" + marshalledMetadata
	}
	return []byte(marshalledURI), nil
}

func unmarshalArguments(source string) (map[string]string, error) {
	arguments := strings.Split(source, "&")
	return unmarshallURIList(arguments)
}

func unmarshallURIList(uriList []string) (map[string]string, error) {
	toReturn := map[string]string{}
	for _, arg := range uriList {
		split := strings.Split(arg, "=")
		toReturn[split[0]] = split[1]
	}
	return toReturn, nil
}

func marshallURIMap(uriMap map[string]string) string {
	var marshalledMap = ""
	if uriMap == nil {
		return marshalledMap
	}

	for key, value := range uriMap {
		marshalledMap += key + "=" + value + "&"
	}
	return marshalledMap[:len(marshalledMap)-1]
}
