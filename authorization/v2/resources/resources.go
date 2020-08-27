package resources

import "github.com/gin-gonic/gin"

// Resource is the interface for a generic resource
type Resource interface {
	// GetResourcePath returns the path to the resource
	GetResourcePath() string
}

// RouterResource is a resource interface for API routers
type RouterResource interface {
	Resource
	// GetAuthToken extracts the authorization token from given request
	GetAuthToken(ctx *gin.Context) string
	// HandleUnauthorized handles an unauthorized request
	HandleUnauthorized(ctx *gin.Context)
}
