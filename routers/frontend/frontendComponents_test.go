package frontend

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/entities"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func Test_navbarDataProvider__returns_correct_model(t *testing.T) {
	setup := setupTest(t, nil, 0)
	setup.testCtx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	setup.testCtx.Request.AddCookie(&http.Cookie{
		Name:   returnToCookie,
		Value:  "return to",
		MaxAge: 1000,
	})

	dataModel, err := navbarDataProvider(setup.testCtx, &setup.router)

	assert.NoError(t, err)
	assert.IsType(t, navbarDataModel{}, dataModel)
	assert.Equal(t, "return to", dataModel.(navbarDataModel).ReturnTo)
}

func Test_navbarDataProvider__returns_empty_string_when_cookie_is_not_defined(t *testing.T) {
	setup := setupTest(t, nil, 0)
	setup.testCtx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	dataModel, err := navbarDataProvider(setup.testCtx, &setup.router)

	assert.NoError(t, err)
	assert.IsType(t, navbarDataModel{}, dataModel)
	assert.Equal(t, "", dataModel.(navbarDataModel).ReturnTo)
}

func Test_personalInformationPanelDataProvider(t *testing.T) {
	tests := []struct {
		name    string
		prep    func(*testSetup)
		wantErr bool
		wantRes personalInformationPanelDataModel
	}{
		{
			name: "should return error when authorizer returns error",
			prep: func(setup *testSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, errors.New("authorizer err")).Times(1)
			},
			wantErr: true,
		},
		{
			name: "should return error when user service returns error",
			prep: func(setup *testSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantErr: true,
		},
		{
			name: "should return correct model",
			prep: func(setup *testSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockUService.EXPECT().GetUserWithID(setup.testCtx, testUserId.Hex()).
					Return(&entities.User{
						Name:  "Bob the Tester",
						Email: "bob@testing.com",
					}, nil).Times(1)
			},
			wantRes: personalInformationPanelDataModel{
				Name:  "Bob the Tester",
				Email: "bob@testing.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, nil, 0)
			defer setup.ctrl.Finish()

			if tt.prep != nil {
				tt.prep(setup)
			}

			attachAuthCookie(setup.testCtx)

			dataModel, err := personalInformationPanelDataProvider(setup.testCtx, &setup.router)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if !reflect.DeepEqual(tt.wantRes, personalInformationPanelDataModel{}) {
				assert.IsType(t, personalInformationPanelDataModel{}, dataModel)
				assert.Equal(t, tt.wantRes, dataModel.(personalInformationPanelDataModel))
			}
		})
	}
}

func Test_teamPanelDataProvider(t *testing.T) {
	tests := []struct {
		name    string
		prep    func(*testSetup)
		wantErr bool
		wantRes teamPanelDataModel
	}{
		{
			name: "should return error when authorizer returns error",
			prep: func(setup *testSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(primitive.ObjectID{}, errors.New("authorizer err")).Times(1)
			},
			wantErr: true,
		},
		{
			name: "should return error when team service returns error",
			prep: func(setup *testSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamForUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantErr: true,
		},
		{
			name: "should return error when user service returns error",
			prep: func(setup *testSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamForUserWithID(setup.testCtx, testUserId.Hex()).
					Return(&entities.Team{}, nil).Times(1)
				setup.mockUService.EXPECT().GetTeammatesForUserWithID(setup.testCtx, testUserId.Hex()).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantErr: true,
		},
		{
			name: "should return expected model",
			prep: func(setup *testSetup) {
				setup.mockAuthorizer.EXPECT().GetUserIdFromToken(testAuthToken).
					Return(testUserId, nil).Times(1)
				setup.mockTService.EXPECT().GetTeamForUserWithID(setup.testCtx, testUserId.Hex()).
					Return(&entities.Team{Name: "Team of Bobs"}, nil).Times(1)
				setup.mockUService.EXPECT().GetTeammatesForUserWithID(setup.testCtx, testUserId.Hex()).
					Return([]entities.User{{Name: "Bob the Tester"}}, nil).Times(1)
				setup.cfg.TeamMembersSoftLimit = 4
			},
			wantRes: teamPanelDataModel{
				Team:                 &entities.Team{Name: "Team of Bobs"},
				Teammates:            []entities.User{{Name: "Bob the Tester"}},
				TeamMembersSoftLimit: 4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, nil, 0)
			defer setup.ctrl.Finish()

			if tt.prep != nil {
				tt.prep(setup)
			}

			attachAuthCookie(setup.testCtx)

			dataModel, err := teamPanelDataProvider(setup.testCtx, &setup.router)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if !reflect.DeepEqual(tt.wantRes, teamPanelDataModel{}) {
				assert.IsType(t, teamPanelDataModel{}, dataModel)
				assert.Equal(t, tt.wantRes, dataModel.(teamPanelDataModel))
			}
		})
	}
}
func Test_usersListPanelDataProvider(t *testing.T) {
	tests := []struct {
		name    string
		prep    func(*testSetup)
		wantErr bool
		wantRes usersListPanelDataModel
	}{
		{
			name: "should return error when user service returns error",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUsers(setup.testCtx).
					Return(nil, errors.New("service err")).Times(1)
			},
			wantErr: true,
		},
		{
			name: "should return correct model",
			prep: func(setup *testSetup) {
				setup.mockUService.EXPECT().GetUsers(setup.testCtx).
					Return([]entities.User{{Name: "Bob the Tester"}, {Name: "Rob the Tester"}}, nil).Times(1)
			},
			wantRes: usersListPanelDataModel{
				Users: []entities.User{{Name: "Bob the Tester"}, {Name: "Rob the Tester"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := setupTest(t, nil, 0)
			defer setup.ctrl.Finish()

			if tt.prep != nil {
				tt.prep(setup)
			}

			attachAuthCookie(setup.testCtx)

			dataModel, err := usersListPanelDataProvider(setup.testCtx, &setup.router)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if !reflect.DeepEqual(tt.wantRes, usersListPanelDataModel{}) {
				assert.IsType(t, usersListPanelDataModel{}, dataModel)
				assert.Equal(t, tt.wantRes, dataModel.(usersListPanelDataModel))
			}
		})
	}
}

func Test_components_have_correct_names(t *testing.T) {
	// REMINDER: if you have to update any values here, you will most likely have to update the user permissions as well
	assert.Equal(t, "Default:Navbar", navbar.name)
	assert.Equal(t, "Default:PersonalInformationPanel", personalInformationPanel.name)
	assert.Equal(t, "TeamPanel", teamPanel.name)
	assert.Equal(t, "UsersListPanel", usersListPanel.name)
}
