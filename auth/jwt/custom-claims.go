package jwt

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// CustomClaims records authorization information
type CustomClaims struct {
	jwt.StandardClaims
	CustomField interface{}
}

// CustomClaimsFactory is used to generate custom claims for convenient injected fields
type CustomClaimsFactory func() *CustomClaims

type CustomClaimsValidateFunction func(*gin.Context, *CustomClaims) error
