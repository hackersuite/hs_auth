package models

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"
)

func Test_Heartbeat__should_return_correct_message(t *testing.T) {
	w := httptest.NewRecorder()
	_, testRouter := gin.CreateTestContext(w)

	router := BaseRouter{}
	testRouter.GET("test", router.Heartbeat)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	testRouter.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	res, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	assert.Equal(t, "{\"status\":\"OK\",\"code\":200,\"message\":\"request to /test received\"}", res)
}
