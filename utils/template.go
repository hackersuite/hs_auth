package utils

import (
	"html/template"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

func LoadTemplate(templateName string, templatePath string) (*template.Template, error) {
	file, err := os.Open(templatePath)
	if err != nil {
		return nil, errors.Wrapf(err, "could not open template file %s", templatePath)
	}

	templateStr, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read template file %s", templatePath)
	}

	template, err := template.New(templateName).Parse(string(templateStr))
	if err != nil {
		return nil, errors.Wrapf(err, "could not parse template %s", templateName)
	}

	return template, nil
}
