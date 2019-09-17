package testutils

import (
	"fmt"
	"os"
	"reflect"
)

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
