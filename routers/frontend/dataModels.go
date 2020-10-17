package frontend

import (
	"github.com/unicsmcr/hs_auth/config"
	"github.com/unicsmcr/hs_auth/entities"
)

type pageDataModel struct {
	Cfg        config.AppConfig
	Alert      string
	Components map[string]interface{}
	CustomPageData
}

type CustomPageData interface{}

type navbarDataModel struct {
	ReturnTo string
}

type teamPanelDataModel struct {
	Team                 *entities.Team
	Teammates            []entities.User
	TeamMembersSoftLimit uint
}

type personalInformationPanelDataModel struct {
	Name  string
	Email string
}

type usersListPanelDataModel struct {
	Users []entities.User
}
