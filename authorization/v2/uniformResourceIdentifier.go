package v2

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/unicsmcr/hs_auth/authorization/v2/resources"
	"net/url"
	"reflect"
	"regexp"
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
	remainingURI, metadata, err := extractURIListFromString(source, "#")
	if err != nil {
		return UniformResourceIdentifier{}, errors.Wrap(ErrInvalidURI, errors.Wrap(err, "could not unmarshall metadata").Error())
	}

	remainingURI, arguments, err := extractURIListFromString(remainingURI, "?")
	if err != nil {
		return UniformResourceIdentifier{}, errors.Wrap(ErrInvalidURI, errors.Wrap(err, "could not unmarshall arguments").Error())
	}

	return UniformResourceIdentifier{
		path:      remainingURI,
		arguments: arguments,
		metadata:  metadata,
	}, nil
}

func extractURIListFromString(source string, sep string) (remainingURI string, uriList map[string]string, error error) {
	sourceSplit := strings.Split(source, sep)

	if len(sourceSplit) > 2 {
		return "", nil, errors.New(fmt.Sprintf("malformed uri, more than two '%s' characters found", sep))
	} else if len(sourceSplit) == 2 {
		unescapedURIList, err := url.QueryUnescape(sourceSplit[1])
		if err != nil {
			return "", nil, errors.Wrap(err, "could not unescape URI list")
		}

		uriList, err := unmarshallURIList(unescapedURIList)
		if err != nil {
			return "", nil, errors.Wrap(err, "could not unmarshall URI List")
		}

		return sourceSplit[0], uriList, nil
	} else {
		return source, nil, nil
	}
}

// MarshalJSON will convert the UniformResourceIdentifier struct into the standard string representation for URIs.
func (uri UniformResourceIdentifier) MarshalJSON() ([]byte, error) {
	var (
		marshalledURI      = uri.path
		marshalledArgs     = marshallURIMap(uri.arguments)
		marshalledMetadata = marshallURIMap(uri.metadata)
	)

	if len(marshalledArgs) > 0 {
		marshalledURI += "?" + url.QueryEscape(marshalledArgs)
	}

	if len(marshalledMetadata) > 0 {
		marshalledURI += "#" + url.QueryEscape(marshalledMetadata)
	}

	return []byte(fmt.Sprintf("\"%s\"", marshalledURI)), nil
}

func (uri *UniformResourceIdentifier) UnmarshalJSON(data []byte) error {
	uriString := string(data)

	if len(uriString) > 0 && uriString[0] == '"' && uriString[len(uriString)-1] == '"' {
		uriString = uriString[1 : len(uriString)-1]
	}

	parsedURI, err := NewURIFromString(uriString)
	if err == nil {
		*uri = parsedURI
	}

	return err
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

	for index, keyValuePair := range keyValuePairs {
		split := strings.Split(keyValuePair, "=")
		if len(split) != 2 {
			return nil, errors.New("malformed key value pair at index " + string(index))
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

	// Remove the extra '&' character introduced when marshaling the uriMap
	return marshalledMap[:len(marshalledMap)-1]
}

// isSubsetOf checks that the URI is a subset of the given URI
func (uri UniformResourceIdentifier) isSubsetOf(target UniformResourceIdentifier) bool {
	// Ensure the target path is a subset of the source path
	if len(uri.path) > len(target.path) {
		return false
	}

	// Compare URI path
	sourcePathComponents := strings.Split(uri.path, ":")
	targetPathComponents := strings.Split(target.path, ":")
	for i, pathComponent := range sourcePathComponents {
		if pathComponent != targetPathComponents[i] {
			return false
		}
	}

	// Validate URI arguments
	for key, targetValue := range target.arguments {
		if sourceValue, ok := uri.arguments[key]; ok {
			match, err := regexp.Match(sourceValue, []byte(targetValue))
			if !match || err != nil {
				// Fail-soft, if the regex is invalid or the regex pattern match fails, the URIs don't match
				return false
			}
		} else {
			// In the case the source URI doesn't contain an argument that exists in the target URI
			// the uri is no longer a subset of the target.
			// e.g. Source = hs:hs_auth and Target = hs:hs_auth?test=1
			// this means, the source is not a subset of the target since it is limited by the argument "test=1"
			return false
		}
	}

	// TODO: Add URI metadata validation. See https://github.com/unicsmcr/hs_auth/pull/91#discussion_r471787861
	return true
}

// isSubsetOfAtLeastOne checks if the URI is a subset of at least one of the given URIs
// Returns true if the uri matched a target uri along with the matching uri from the target set
func (uri UniformResourceIdentifier) isSubsetOfAtLeastOne(targets []UniformResourceIdentifier) (bool, UniformResourceIdentifier) {
	for i := 0; i < len(targets); i++ {
		if uri.isSubsetOf(targets[i]) {
			return true, targets[i]
		}
	}
	return false, UniformResourceIdentifier{}
}
