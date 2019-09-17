package models

import (
	"github.com/gin-gonic/gin"
)

// APIError is a struct to store a standard API error
type APIError Response

func (e *APIError) Error() string {
	return e.Err
}

// NewAPIError creates an APIError with given status and error message
func NewAPIError(status int, err string) APIError {
	return APIError{
		Status: status,
		Err:    err,
	}
}

// SendAPIError sends an error with given status and error message to the user
func SendAPIError(ctx *gin.Context, status int, err string) {
	ctx.JSON(status, NewAPIError(status, err))
	ctx.Abort()
}
