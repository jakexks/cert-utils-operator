package controller

import (
	"github.com/raffaelespazzoli/secret-utils-operator/pkg/controller/route"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, route.Add)
}
