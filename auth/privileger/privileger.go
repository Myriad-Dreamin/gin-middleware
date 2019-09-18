package privileger

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Validator interface {
	Enforce(...interface{}) (bool, error)
}

// MiddleWare does not check the identity of user
type MiddleWare struct {
	v      Validator
	uTable string
	idKey string
}

func NewMiddleWare(v Validator, uTable,idKey string) *MiddleWare {
	return &MiddleWare{
		v:      v,
		uTable: uTable,
		idKey: idKey,
	}
}

func (middleware *MiddleWare) Build() gin.HandlerFunc {
	return func(c *gin.Context) {
		if ok, err := middleware.CheckPermission(c); err != nil {
			_ = c.AbortWithError(http.StatusForbidden, err)
			return
		} else if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}
}

func (middleware *MiddleWare) CheckPermission(c *gin.Context) (bool, error) {
	var uid string
	if uid = c.GetString(middleware.idKey); len(uid) == 0 {
		return false, errors.New("missing uid")
	}
	return middleware.v.Enforce(middleware.uTable+uid, c.Request.URL.Path, c.Request.Method)
}
