package common

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
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

type UniformResourceIdentifiers []UniformResourceIdentifier

// NewUriFromRequest creates a UniformResourceIdentifier from a gin request to the given resource and handler
func NewUriFromRequest(resource Resource, handler gin.HandlerFunc, ctx *gin.Context) UniformResourceIdentifier {
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
	var uriString string
	err := json.Unmarshal(data, &uriString)
	if err != nil {
		return err
	}

	parsedURI, err := NewURIFromString(uriString)
	if err == nil {
		*uri = parsedURI
	}

	return err
}

func (uris *UniformResourceIdentifiers) MarshalJSON() ([]byte, error) {
	var uriStringBuilder strings.Builder

	for i, uri := range *uris {
		uriString, _ := json.Marshal(uri)
		uriStringBuilder.Write(uriString)

		if i < len(*uris)-1 {
			uriStringBuilder.WriteRune(',')
		}
	}

	return []byte(fmt.Sprintf("[%s]", uriStringBuilder.String())), nil
}

func (uris *UniformResourceIdentifiers) UnmarshalJSON(data []byte) error {
	var uriList []interface{}
	err := json.Unmarshal(data, &uriList)
	if err != nil {
		return err
	}

	if len(uriList) == 0 {
		return nil
	}

	parsedURIs := make(UniformResourceIdentifiers, len(uriList))
	for i, uriString := range uriList {
		parsedURIs[i], err = NewURIFromString(uriString.(string))
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal uri")
		}
	}

	*uris = parsedURIs
	return nil
}

// Implements the ValueMarshaler interface of the mongo pkg.
func (uris UniformResourceIdentifiers) MarshalBSONValue() (bsontype.Type, []byte, error) {
	marshalledURIs := make([]string, len(uris))
	for i, uri := range uris {
		// Ignore the error since we are guaranteed to get a valid string
		marshalledURI, _ := uri.MarshalJSON()

		// MarshalJSON en-quotes the marshalled URI, so we unquote it here
		marshalledURIs[i] = string(marshalledURI[1 : len(marshalledURI)-1])
	}

	allURIs := strings.Join(marshalledURIs, ",")
	return bsontype.String, bsoncore.AppendString(nil, allURIs), nil
}

// Implements the ValueUnmarshaler interface of the mongo pkg.
func (uris *UniformResourceIdentifiers) UnmarshalBSONValue(_ bsontype.Type, bytes []byte) error {
	urisCombined, _, _ := bsoncore.ReadString(bytes)
	allURIStrings := strings.Split(urisCombined, ",")

	unmarshalledURIs := make(UniformResourceIdentifiers, len(allURIStrings))
	for i, uriString := range allURIStrings {
		parsedURI, err := NewURIFromString(uriString)
		if err != nil {
			return err
		}
		unmarshalledURIs[i] = parsedURI
	}

	*uris = unmarshalledURIs
	return nil
}

// Implements the Unmarshal interface of the yaml pkg.
func (uris *UniformResourceIdentifiers) UnmarshalYAML(unmarshal func(interface{}) error) error {
	yamlURISequence := make([]string, 0)
	err := unmarshal(&yamlURISequence)
	if err != nil {
		return err
	}

	*uris = make([]UniformResourceIdentifier, len(yamlURISequence))
	for i, uri := range yamlURISequence {
		parsedURI, err := NewURIFromString(uri)
		if err == nil {
			(*uris)[i] = parsedURI
		}
	}

	return nil
}

func getHandlerName(handler gin.HandlerFunc) string {
	parts := strings.Split(runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name(), ".")
	funcName := parts[len(parts)-1]
	return strings.TrimSuffix(funcName, "-fm")
}

func getRequestArguments(ctx *gin.Context) map[string]string {
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

	// form
	ctx.MultipartForm() // triggering a parse on the form arguments
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
			return nil, errors.New(fmt.Sprintf("malformed key value pair at index %d", index))
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

// isSupersetOf checks that the URI is a superset of the given URI
func (uri UniformResourceIdentifier) isSupersetOf(target UniformResourceIdentifier) bool {
	// Ensure the source path is a superset of the target
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

	// The source uri is a superset of the target uri, we can return early in this case
	if len(sourcePathComponents) <= len(targetPathComponents) && uri.arguments == nil {
		return true
	}

	// Validate URI arguments
	for key, sourceValue := range uri.arguments {
		// edge-case for empty string in the source URI arguments
		if len(sourceValue) == 0 {
			if target.arguments[key] != sourceValue {
				return false
			} else {
				continue
			}
		}

		if targetValue, ok := target.arguments[key]; ok {
			if match, err := regexp.Match(sourceValue, []byte(targetValue)); !match || err != nil {
				// the argument value on the target URI is not within the argument limitation
				// on the source URI
				return false
			}
		} else {
			// target URI does not have an argument limitation that is present
			// on the source URI, source URI is not a superset of the target URI
			return false
		}
	}

	return true
}

// GetAllSupersets checks if the URI is a superset of the target and returns all those matching target uris
func (uri UniformResourceIdentifier) GetAllSupersets(targets []UniformResourceIdentifier) []UniformResourceIdentifier {
	var matchedUris UniformResourceIdentifiers
	for i := 0; i < len(targets); i++ {
		if uri.isSupersetOf(targets[i]) {
			matchedUris = append(matchedUris, targets[i])
		}
	}
	return matchedUris
}

// IsSupersetOfAtLeastOne checks if the URI is a superset of at least one of the given URIs
func (uri UniformResourceIdentifier) IsSupersetOfAtLeastOne(targets []UniformResourceIdentifier) bool {
	for i := 0; i < len(targets); i++ {
		if uri.isSupersetOf(targets[i]) {
			return true
		}
	}
	return false
}

func (uri UniformResourceIdentifier) GetMetadata() map[string]string {
	return uri.metadata
}
