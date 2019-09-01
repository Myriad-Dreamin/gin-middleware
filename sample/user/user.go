package main

import (
	"net/http"

	jwt "github.com/Myriad-Dreamin/gin-middleware/auth/jwt"

	"github.com/Myriad-Dreamin/core-oj/log"
	morm "github.com/Myriad-Dreamin/gin-middleware/sample/user/orm"
	"github.com/gin-gonic/gin"
)

// UserService defines handler functions of code router
type UserService struct {
	UserX    *morm.UserX
	logger   log.TendermintLogger
	codePath string
}

// NewUserService return a pointer of UserService
func NewUserService(userX *morm.UserX, logger log.TendermintLogger) *UserService {
	return &UserService{
		UserX:  userX,
		logger: logger,
	}
}

// type RegisterInfo struct {
// 	Name     string `bind:"name" json:"name"`
// 	Password []byte `bind:"password" json:"password"`
// }

func (us *UserService) Register(c *gin.Context) {
	var user = new(morm.User)
	if err := c.Bind(user); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code":  CodeBindError,
			"error": err.Error(),
		})
		return
	}

	aff, err := user.InsertWithDefault()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	} else if aff == 0 {
		c.JSON(http.StatusOK, gin.H{
			"code":  CodeInsertError,
			"error": "existed",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code":           CodeOK,
		"id":             user.ID,
		"exp":            user.Exp,
		"solved_problem": user.SolvedProblems,
	})
}

// User example
type LoginRequest struct {
	ID       int    `form:"id" json:"id"`
	Name     string `form:"name" json:"name"`
	Email    string `form:"email" json:"email"`
	Phone    string `form:"phone" json:"phone"`
	Password string `form:"password" json:"password" xorm:"'password'" binding:"required"`
}

func (us *UserService) Login(c *gin.Context) {
	var req = new(LoginRequest)
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code":  CodeBindError,
			"error": err.Error(),
		})
		return
	}

	var user *morm.User
	var err error
	if req.ID != 0 {
		user, err = us.UserX.Query(req.ID)
	} else if len(req.Name) != 0 {
		user, err = us.UserX.QueryName(req.Name)
	} else if len(req.Email) != 0 {
		user, err = us.UserX.QueryEmail(req.Email)
	} else if len(req.Phone) != 0 {
		user, err = us.UserX.QueryPhone(req.Phone)
	} else {
		c.JSON(http.StatusOK, gin.H{
			"code": CodeUserIDMissing,
		})
		return
	}
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	if user == nil {
		c.JSON(http.StatusOK, gin.H{
			"code": CodeNotFound,
		})
		return
	}

	if user.Password != req.Password {
		c.JSON(http.StatusOK, gin.H{
			"code": CodeUserWrongPassword,
		})
		return
	}

	if token, err := jwt.GenerateToken(user.ID, 3600); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code":  CodeAuthGenerateTokenError,
			"error": err.Error(),
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"code":           CodeOK,
			"id":             user.ID,
			"exp":            user.Exp,
			"solved_problem": user.SolvedProblems,
			"token":          token,
		})
	}

}
