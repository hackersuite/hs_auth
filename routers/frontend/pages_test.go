package frontend

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/unicsmcr/hs_auth/authorization/v2/common"
	rcommon "github.com/unicsmcr/hs_auth/routers/common"
	"testing"
)

func Test_newFrontendPage_returns_expected_page(t *testing.T) {
	testComponent := frontendComponent{
		name: "testComponent",
	}

	page, err := newFrontendPage("testPage", "testTemplate", frontendComponents{testComponent})

	componentUri, err := common.NewURIFromString(fmt.Sprintf("%s:testPageComponents:testComponent", rcommon.FrontendResourcePath))
	assert.NoError(t, err)

	assert.NoError(t, err)
	assert.Equal(t, frontendPage{
		name:          "testPage",
		templateName:  "testTemplate",
		componentURIs: common.UniformResourceIdentifiers{componentUri},
		components:    frontendComponents{testComponent},
	}, page)
}

func Test_newFrontendPage_returns_error_when_component_uri_is_invalid(t *testing.T) {
	testComponent := frontendComponent{
		name: "testComponent?invaliduri",
	}

	_, err := newFrontendPage("testPage", "testTemplate", frontendComponents{testComponent})

	assert.Error(t, err)
}

func Test_getComponentsWithURIs_returns_correct_components(t *testing.T) {
	testComponent1 := frontendComponent{
		name: "testComponent1",
	}
	testComponent2 := frontendComponent{
		name: "testComponent2",
	}

	page, err := newFrontendPage("testPage", "testTemplate", frontendComponents{testComponent1, testComponent2})
	assert.NoError(t, err)

	component2Uri, err := common.NewURIFromString(fmt.Sprintf("%s:testPageComponents:%s", rcommon.FrontendResourcePath, testComponent2.name))
	assert.NoError(t, err)

	components := page.getComponentsWithURIs(common.UniformResourceIdentifiers{component2Uri})
	assert.Equal(t, frontendComponents{testComponent2}, components)
}

func Test_pages_contain_correct_components(t *testing.T) {
	assert.Len(t, profilePage.components, 4)
	assert.True(t, containsComponent(profilePage, teamPanel))
	assert.True(t, containsComponent(profilePage, personalInformationPanel))
	assert.True(t, containsComponent(profilePage, usersListPanel))
	assert.True(t, containsComponent(profilePage, navbar))
}

func Test_pages_use_correct_templates(t *testing.T) {
	assert.Equal(t, "profile.gohtml", profilePage.templateName)
	assert.Equal(t, "login.gohtml", loginPage.templateName)
	assert.Equal(t, "register.gohtml", registerPage.templateName)
	assert.Equal(t, "registerEnd.gohtml", registerEndPage.templateName)
	assert.Equal(t, "forgotPassword.gohtml", forgotPasswordPage.templateName)
	assert.Equal(t, "forgotPasswordEnd.gohtml", forgotPasswordEndPage.templateName)
	assert.Equal(t, "resetPassword.gohtml", resetPasswordPage.templateName)
	assert.Equal(t, "resetPasswordEnd.gohtml", resetPasswordEndPage.templateName)
	assert.Equal(t, "verifyEmail.gohtml", verifyEmailPage.templateName)
	assert.Equal(t, "emailVerifyResend.gohtml", verifyEmailResendPage.templateName)
	assert.Equal(t, "emailNotVerified.gohtml", emailUnverifiedPage.templateName)
}

func Test_pages_have_correct_names(t *testing.T) {
	// REMINDER: if you have to update any values here, you will most likely have to update the user permissions as well
	assert.Equal(t, "ProfilePage", profilePage.name)
	assert.Equal(t, "LoginPage", loginPage.name)
	assert.Equal(t, "RegisterPage", registerPage.name)
	assert.Equal(t, "RegisterEndPage", registerEndPage.name)
	assert.Equal(t, "ForgotPasswordPage", forgotPasswordPage.name)
	assert.Equal(t, "ForgotPasswordEndPage", forgotPasswordEndPage.name)
	assert.Equal(t, "ResetPasswordPage", resetPasswordPage.name)
	assert.Equal(t, "ResetPasswordEndPage", resetPasswordEndPage.name)
	assert.Equal(t, "VerifyEmailPage", verifyEmailPage.name)
	assert.Equal(t, "VerifyEmailResendPage", verifyEmailResendPage.name)
	assert.Equal(t, "EmailUnverifiedPage", emailUnverifiedPage.name)
}

func containsComponent(page frontendPage, component frontendComponent) bool {
	for _, pageComponent := range page.components {
		if pageComponent.name == component.name {
			return true
		}
	}
	return false
}
