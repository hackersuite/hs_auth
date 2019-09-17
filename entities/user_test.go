package entities

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func Test_Password__should_be_ommitted_when_marshalling_user_to_JSON(t *testing.T) {
	user := User{
		ID:       primitive.NewObjectID(),
		Password: "test password",
	}

	userJSON, err := json.Marshal(user)
	assert.NoError(t, err)

	var unmarshalledUser User
	err = json.Unmarshal(userJSON, &unmarshalledUser)
	assert.NoError(t, err)

	assert.Empty(t, unmarshalledUser.Password)
}
