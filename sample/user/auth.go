package main

import (
	"net/http"

	"github.com/Myriad-Dreamin/core-oj/log"
	rbac "github.com/Myriad-Dreamin/gin-middleware/sample/user/rbac"
	"github.com/gin-gonic/gin"
)

type AuthService struct {
	logger   log.TendermintLogger
	codePath string
}

// NewAuthService return a pointer of AuthService
func NewAuthService(logger log.TendermintLogger) *AuthService {
	return &AuthService{
		logger: logger,
	}
}

type AddPolicyReq struct {
	Subject string `form:"subject" json:"subject" binding:"required"`
	Object  string `form:"object" json:"object" binding:"required"`
	Action  string `form:"action" json:"action" binding:"required"`
}

func (as *AuthService) AddPolicy(c *gin.Context) {
	var req = new(AddPolicyReq)
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code":  CodeBindError,
			"error": err.Error(),
		})
		return
	}

	added, err := rbac.AddPolicy(req.Subject, req.Object, req.Action)

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code":  CodeInsertError,
			"error": err.Error(),
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"code":  CodeOK,
			"added": added,
		})
	}

	return
}

type AddGroupingPolicyReq struct {
	Subject string `form:"subject" json:"subject" binding:"required"`
	Group   string `form:"group" json:"group" binding:"required"`
}

func (as *AuthService) AddGroupingPolicy(c *gin.Context) {
	var req = new(AddGroupingPolicyReq)
	if err := c.Bind(req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code":  CodeBindError,
			"error": err.Error(),
		})
		return
	}

	added, err := rbac.AddGroupingPolicy(req.Subject, req.Group)

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code":  CodeInsertError,
			"error": err.Error(),
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"code":  CodeOK,
			"added": added,
		})
	}

	return
}

func (as *AuthService) GetPolicy(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"code":   CodeOK,
		"policy": rbac.GetPolicy(),
	})
}

func (as *AuthService) GetGroupingPolicy(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"code":   CodeOK,
		"policy": rbac.GetGroupingPolicy(),
	})
}
