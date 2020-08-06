package v2

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/unicsmcr/hs_auth/authorization/v2/resources"
	"reflect"
	"runtime"
	"strings"
)

// UniformResourceIdentifier stores an identifier for a resource
type UniformResourceIdentifier struct {
	path      string
	arguments map[string]string
	metadata  map[string]string
}

// NewUriFromRequest creates a UniformResourceIdentifier from a gin request to the given resource and handler
func NewUriFromRequest(resource resources.Resource, handler gin.HandlerFunc, ctx *gin.Context) UniformResourceIdentifier {
	return UniformResourceIdentifier{
		path:      fmt.Sprintf("%s:%s", resource.GetResourcePath(), getHandlerName(handler)),
		arguments: getRequestArguments(ctx),
	}
}

// NewURIFromString parses the string representation of a URI into the UniformResourceIdentifier struct.
// NewURIFromString expects the string to be of the following form, otherwise ErrInvalidURI is returned.
// hs:<service_name>:<subsystem>:<version>:<category>:<resource_name>?<allowed_arguments>#<permission_metadata>
func NewURIFromString(source string) (UniformResourceIdentifier, error) {
	var (
		arguments map[string]string
		metadata  map[string]string
		err       error
	)

	pathMetadataSplit := strings.Split(source, "#")
	if len(pathMetadataSplit) > 2 {
		return UniformResourceIdentifier{}, ErrInvalidURI
	} else if len(pathMetadataSplit) == 2 {
		metadata, err = unmarshallURIList(pathMetadataSplit[1])

		if err != nil {
			return UniformResourceIdentifier{}, err
		}
	}

	pathArgumentSplit := strings.Split(pathMetadataSplit[0], "?")
	if len(pathArgumentSplit) > 2 {
		return UniformResourceIdentifier{}, ErrInvalidURI
	} else if len(pathArgumentSplit) == 2 {
		arguments, err = unmarshallURIList(pathArgumentSplit[1])

		if err != nil {
			return UniformResourceIdentifier{}, err
		}
	}

	return UniformResourceIdentifier{
		path:      pathArgumentSplit[0],
		arguments: arguments,
		metadata:  metadata,
	}, nil
}

// MarshalJSON will convert the UniformResourceIdentifier struct into the standard string representation for URIs.
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

	return []byte(fmt.Sprintf("\"%s\"", marshalledURI)), nil
}

func getHandlerName(handler gin.HandlerFunc) string {
	parts := strings.Split(runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name(), ".")
	funcName := parts[len(parts)-1]
	return strings.TrimRight(funcName, "-fm")
}

func getRequestArguments(ctx *gin.Context) map[string]string {
	// TODO: tidy this up once string -> URI -> string mapping is done
	args := make(map[string]string)

	// path
	for _, param := range ctx.Params {
		key := fmt.Sprintf("path_%s", param.Key)
		args[key] = param.Value
	}

	// query
	for key, value := range ctx.Request.URL.Query() {
		args[fmt.Sprintf("query_%s", key)] = strings.Join(value, ",")
	}

	// query
	for key, value := range ctx.Request.PostForm {
		args[fmt.Sprintf("postForm_%s", key)] = strings.Join(value, ",")
	}

	return args
}

func unmarshallURIList(source string) (map[string]string, error) {
	uriListMapping := map[string]string{}
	keyValuePairs := strings.Split(source, "&")

	for _, keyValuePair := range keyValuePairs {
		split := strings.Split(keyValuePair, "=")
		if len(split) != 2 {
			return nil, ErrInvalidURI
		}
		uriListMapping[split[0]] = split[1]
	}

	return uriListMapping, nil
}

func marshallURIMap(uriMap map[string]string) string {
	var marshalledMap string
	if uriMap == nil || len(uriMap) == 0 {
		return marshalledMap
	}

	for key, value := range uriMap {
		marshalledMap += key + "=" + value + "&"
	}

	return marshalledMap[:len(marshalledMap)-1]
}
