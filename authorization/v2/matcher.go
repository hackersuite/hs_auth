package v2

import (
	"strings"
)

//hs:<service_name>:<subsystem>:<version>:<category>:<resource_name>?<allowed_arguments>#<permission_metadata>
type URI struct {
	path      string
	arguments map[string]string
	metadata  map[string]string
}

// hs:<service_name>:<subsystem>:<version>:<category>:<resource_name>?<allowed_arguments>#<permission_metadata>
func NewURIFromString(source string) (URI, error) {
	var (
		arguments map[string]string = nil
		metadata  map[string]string = nil
	)

	pathArgumentSplit := strings.Split(source, "?")
	path := pathArgumentSplit[0]

	if len(pathArgumentSplit) > 2 {
		return URI{}, ErrInvalidURI
	}

	if len(pathArgumentSplit) == 2 {
		var err error

		argumentsMetadataSplit := strings.Split(pathArgumentSplit[1], "#")
		arguments, err = unmarshalArguments(argumentsMetadataSplit[0])
		if err != nil {
			return URI{}, err
		}

		if len(argumentsMetadataSplit) > 1 {
			metadata, err = unmarshalArguments(argumentsMetadataSplit[1])
			if err != nil {
				return URI{}, err
			}
		}
	}

	return URI{
		path:      path,
		arguments: arguments,
		metadata:  metadata,
	}, nil
}

func (uri URI) MarshalJSON() string {
	var (
		marshalledURI = uri.path
		marshalledArgs = marshallURIMap(uri.arguments)
		marshalledMetadata = marshallURIMap(uri.metadata)
	)

	if len(marshalledArgs) > 0 {
		marshalledURI += "?" + marshalledArgs
	}

	if len(marshalledMetadata) > 0 {
		marshalledURI += "#" + marshalledMetadata
	}
	return marshalledURI
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
	return marshalledMap[:len(marshalledMap) - 1]
}
