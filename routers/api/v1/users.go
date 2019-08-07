package v1

import (
	"net/http"

	"github.com/unicsmcr/hs_auth/routers/api/models"

	"github.com/gin-gonic/gin"
)

func (r APIV1Router) GetUsers(c *gin.Context) {
	users, err := r.userService.GetUsers(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.Error{
			Status: http.StatusInternalServerError,
			Err:    err,
		})
		return
	}

	c.JSON(http.StatusOK, users)
}

func Login(c *gin.Context) {
}
