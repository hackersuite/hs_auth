package testutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"

	"github.com/gin-gonic/gin"
)

// UnmarshallResponse unmarshalls the reponse in res and stores it in out
func UnmarshallResponse(res *bytes.Buffer, out interface{}) error {
	actualResStr, err := res.ReadString('\x00')
	if err.Error() != "EOF" {
		return err
	}

	err = json.Unmarshal([]byte(actualResStr), out)
	return nil
}

// AddRequestWithFormParamsToCtx attaches a request with given method and form params to the context
func AddRequestWithFormParamsToCtx(ctx *gin.Context, method string, params map[string]string) {
	data := url.Values{}
	for key, val := range params {
		data.Add(key, val)
	}

	req := httptest.NewRequest(method, "/test", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	ctx.Request = req
}

// AddUrlParamsToCtx attaches a request with given method and url params to the context
func AddUrlParamsToCtx(ctx *gin.Context, params map[string]string) {
	p := gin.Params{}
	for key, val := range params {
		p = append(p, gin.Param{
			Key:   key,
			Value: val,
		})
	}

	ctx.Params = p
}

// SetEnvVars sets given environment variables and provides a callback function to restore the variables to their initial values
func SetEnvVars(vars map[string]string) (restoreVars func()) {
	initialValues := map[string]string{}
	unsetVars := map[string]bool{}

	for name, value := range vars {
		initialValue, exists := os.LookupEnv(name)
		if exists {
			initialValues[name] = initialValue
		} else {
			unsetVars[name] = true
		}

		err := os.Setenv(name, value)
		if err != nil {
			panic(err)
		}
	}

	return func() {
		for name, value := range initialValues {
			err := os.Setenv(name, value)
			if err != nil {
				panic(err)
			}
		}

		for name := range unsetVars {
			err := os.Unsetenv(name)
			if err != nil {
				panic(err)
			}
		}
	}
}

// UnsetVars unsets given environment variables and provides a callback function to restore the variables to their initial values
func UnsetVars(vars ...string) (restoreVars func()) {
	initialValues := map[string]string{}
	for _, name := range vars {
		initialValue, exists := os.LookupEnv(name)
		if exists {
			initialValues[name] = initialValue
		}

		err := os.Unsetenv(name)
		if err != nil {
			panic(err)
		}
	}

	return func() {
		for name, value := range initialValues {
			err := os.Setenv(name, value)
			if err != nil {
				panic(err)
			}
		}
	}
}

// RouterGroupMatcher matches gin router groups with given path
type RouterGroupMatcher struct {
	// Path is the base path of the router groups to match
	Path string
}

// Matches implements the gomock.Matcher interface
func (r RouterGroupMatcher) Matches(x interface{}) bool {
	val := reflect.ValueOf(x)
	if reflect.Zero(reflect.TypeOf(x)) == val {
		return false
	}
	// fetching reference to BasePath
	basePathMethod := val.MethodByName("BasePath")
	if reflect.Zero(reflect.TypeOf(basePathMethod)) == basePathMethod {
		return false
	}
	// calling BasePath
	values := basePathMethod.Call([]reflect.Value{})
	if len(values) != 1 {
		return false
	}
	// checking if value is string
	if !values[0].Type().AssignableTo(reflect.TypeOf("")) {
		return false
	}

	if values[0].String() != r.Path {
		return false
	}
	return true
}

func (r RouterGroupMatcher) String() string {
	return fmt.Sprintf("router group's base path is %s", r.Path)
}
