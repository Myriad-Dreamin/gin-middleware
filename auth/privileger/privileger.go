package privileger

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Validator interface {
	Enforce(...interface{}) (bool, error)
}

// MiddleWare does not check the identity of user
type MiddleWare struct {
	v      Validator
	utable string
}

func NewMiddleWare(v Validator, utable string) *MiddleWare {
	return &MiddleWare{
		v:      v,
		utable: utable,
	}
}

func (middleware *MiddleWare) Build() gin.HandlerFunc {
	return func(c *gin.Context) {
		fmt.Println("toggled")
		if ok, err := middleware.CheckPermission(c); err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		} else if !ok {
			c.AbortWithError(http.StatusUnauthorized, err)
			return
		}
	}
}

func (middleware *MiddleWare) CheckPermission(c *gin.Context) (bool, error) {
	var uid string
	if uid = c.GetHeader("uid"); len(uid) == 0 {
		return false, errors.New("missing uid")
	}
	return middleware.v.Enforce(middleware.utable+uid, c.Request.URL.Path, c.Request.Method)
}
