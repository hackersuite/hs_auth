package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_MarshalJSON__should_return_correct_string_for_each_auth_level(t *testing.T) {
	tests := []struct{
		name string
		authLvl AuthLevel
		expectedResult string
	}{
		{
			name: "applicant",
			authLvl:Applicant,
			expectedResult:"\"applicant\"",
		},
		{
			name: "attendee",
			authLvl:Attendee,
			expectedResult:"\"attendee\"",
		},
		{
			name: "volunteer",
			authLvl:Volunteer,
			expectedResult:"\"volunteer\"",
		},
		{
			name: "organiser",
			authLvl:Organiser,
			expectedResult:"\"organiser\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.authLvl.MarshalJSON()
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedResult, string(result))
		})
	}
}

func Test_MarshalJSON__should_return_ErrUnknownAuthLevel_for_unregistered_auth_level(t *testing.T) {
	fakeAuthLvl := AuthLevel(9000)

	stringLvl, err := fakeAuthLvl.MarshalJSON()

	assert.Error(t, err)
	assert.Nil(t, stringLvl)
}


func Test_UnmarshalJSON__should_return_correct_auth_levels_for_registered_auth_level_strings(t *testing.T) {
	tests := []struct{
		name string
		stringAuthLvl string
		expectedAuthLvl AuthLevel
	}{
		{
			name: "applicant",
			stringAuthLvl:"\"applicant\"",
			expectedAuthLvl:Applicant,
		},
		{
			name: "attendee",
			stringAuthLvl:"\"attendee\"",
			expectedAuthLvl:Attendee,
		},
		{
			name: "volunteer",
			stringAuthLvl:"\"volunteer\"",
			expectedAuthLvl:Volunteer,
		},
		{
			name: "organiser",
			stringAuthLvl:"\"organiser\"",
			expectedAuthLvl:Organiser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testAuthLvl AuthLevel
			err := testAuthLvl.UnmarshalJSON([]byte(tt.stringAuthLvl))
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedAuthLvl, testAuthLvl)
		})
	}
}


func Test_UnmarshalJSON__should_return_ErrUnknownAuthLevel_for_unregistered_auth_level(t *testing.T) {
	var testAuthLvl AuthLevel

	err := testAuthLvl.UnmarshalJSON([]byte("unregistered auth level"))

	assert.Error(t, err)
	assert.Zero(t, testAuthLvl)
}