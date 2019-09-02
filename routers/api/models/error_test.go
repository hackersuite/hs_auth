package models

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/stretchr/testify/assert"
)

func Test_Error__should_return_value_of_Err(t *testing.T) {
	err := APIError{
		Err: "testerr",
	}

	assert.Equal(t, "testerr", err.Error())
}

func Test_NewAPIError__should_return_correct_APIError(t *testing.T) {
	err := NewAPIError(http.StatusOK, "testerr")

	assert.Equal(t, http.StatusOK, err.Status)
	assert.Equal(t, "testerr", err.Err)
}

func Test_SendAPIError__should_send_correct_message(t *testing.T) {
	w := httptest.NewRecorder()
	testCtx, _ := gin.CreateTestContext(w)

	expectedErr := NewAPIError(http.StatusOK, "testerr")

	SendAPIError(testCtx, expectedErr.Status, expectedErr.Err)

	assert.Equal(t, expectedErr.Status, w.Code)

	actualErrString, err := w.Body.ReadString('\x00')
	assert.Equal(t, "EOF", err.Error())

	expectedErrString, err := json.Marshal(expectedErr)
	assert.NoError(t, err)

	assert.Equal(t, string(expectedErrString), actualErrString)
}
