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
