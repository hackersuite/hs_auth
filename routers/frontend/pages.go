package frontend

import (
	"fmt"
	"github.com/pkg/errors"
	authCommon "github.com/unicsmcr/hs_auth/authorization/v2/common"
	"github.com/unicsmcr/hs_auth/routers/common"
	"reflect"
)

var (
	profilePage, _ = newFrontendPage("ProfilePage", "profile.gohtml",
		frontendComponents{
			teamPanel,
			personalInformationPanel,
			usersListPanel,
			navbar,
		})

	loginPage, _ = newFrontendPage("LoginPage", "login.gohtml", nil)

	registerPage, _    = newFrontendPage("RegisterPage", "register.gohtml", nil)
	registerEndPage, _ = newFrontendPage("RegisterEndPage", "registerEnd.gohtml", nil)

	forgotPasswordPage, _    = newFrontendPage("ForgotPasswordPage", "forgotPassword.gohtml", nil)
	forgotPasswordEndPage, _ = newFrontendPage("ForgotPasswordEndPage", "forgotPasswordEnd.gohtml", nil)

	resetPasswordPage, _    = newFrontendPage("ResetPasswordPage", "resetPassword.gohtml", nil)
	resetPasswordEndPage, _ = newFrontendPage("ResetPasswordEndPage", "resetPasswordEnd.gohtml", nil)

	verifyEmailPage, _       = newFrontendPage("VerifyEmailPage", "verifyEmail.gohtml", nil)
	verifyEmailResendPage, _ = newFrontendPage("VerifyEmailResendPage", "emailVerifyResend.gohtml", nil)
	emailUnverifiedPage, _   = newFrontendPage("EmailUnverifiedPage", "emailNotVerified.gohtml", nil)
)

func newFrontendPage(pageName, templatePath string, components frontendComponents) (frontendPage, error) {
	var componentURIs = make(authCommon.UniformResourceIdentifiers, 0, len(components))
	for _, component := range components {
		uri, err := authCommon.NewURIFromString(fmt.Sprintf("%s:%sComponents:%s", common.FrontendResourcePath, pageName, component.name))
		if err != nil {
			return frontendPage{}, errors.Wrap(err, fmt.Sprintf("could not create URI for component %s", component.name))
		}

		componentURIs = append(componentURIs, uri)
	}

	return frontendPage{
		pageName,
		templatePath,
		componentURIs,
		components,
	}, nil
}

type frontendPage struct {
	name          string
	templateName  string
	componentURIs authCommon.UniformResourceIdentifiers
	components    frontendComponents
}

func (p frontendPage) getComponentsWithURIs(uris authCommon.UniformResourceIdentifiers) frontendComponents {
	var components = make(frontendComponents, 0)
	for _, requestedUri := range uris {
		for index, pageComponentUri := range p.componentURIs {
			if reflect.DeepEqual(requestedUri, pageComponentUri) {
				components = append(components, p.components[index])
			}
		}
	}

	return components
}
