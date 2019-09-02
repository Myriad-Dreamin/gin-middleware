package jwt

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var (
	signKey = "Myriad-Dreamin"
)

// GetSignKey .
func GetSignKey() string {
	return signKey
}

// SetSignKey .
func SetSignKey(key string) string {
	signKey = key
	return signKey
}

// GenerateToken with expexpire time
func GenerateToken(id int, expireSecond int64) (string, error) {
	return NewMiddleWare().CreateToken(CustomClaims{
		id,
		jwt.StandardClaims{
			NotBefore: int64(time.Now().Unix() - 10),
			ExpiresAt: int64(time.Now().Unix() + expireSecond),
			Issuer:    signKey,
		},
	})
}

// Middleware customizes the jwt-middleware
type Middleware struct {
	SigningAlgorithm             string
	JWTHeaderKey                 string
	JWTHeaderPrefixWithSplitChar string
	SigningKey                   []byte

	// Public key file for asymmetric algorithms
	PubKeyFile string

	// Private key
	privKey *rsa.PrivateKey

	// Public key
	pubKey *rsa.PublicKey

	MaxRefresh time.Duration
}

// CustomClaims records authorization information
type CustomClaims struct {
	ID int `json:"id"`
	jwt.StandardClaims
}

// NewMiddleWare return default middleware setting
func NewMiddleWare() *Middleware {
	return &Middleware{
		SigningAlgorithm:             "HS256",
		JWTHeaderKey:                 "Authorization",
		JWTHeaderPrefixWithSplitChar: "Bearer ",
		SigningKey:                   []byte(GetSignKey()),
		// MaxRefresh: default zero
	}
}

// Build return the middleware
func (middleware *Middleware) Build() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := middleware.CheckIfTokenExpire(c)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": -1,
				"msg":  err.Error(),
			})
			c.Abort()
			return
		}
		c.Set("claims", claims)

		// todo: authorize identity

	}
}

// CreateToken generate a token
func (middleware *Middleware) CreateToken(claims CustomClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(middleware.SigningKey)
}

// RefreshToken if ok
func (middleware *Middleware) RefreshToken(c *gin.Context) (string, error) {
	claims, err := middleware.CheckIfTokenExpire(c)
	if err != nil {
		return "", err
	}
	claims.StandardClaims.ExpiresAt = jwt.TimeFunc().Add(1 * time.Hour).Unix()
	return middleware.CreateToken(*claims)
}

// CheckIfTokenExpire check if token expire
func (middleware *Middleware) CheckIfTokenExpire(c *gin.Context) (*CustomClaims, error) {
	token, err := middleware.ParseToken(c)

	if err != nil {
		// If we receive an error, and the error is anything other than a single
		// ValidationErrorExpired, we want to return the error.
		// If the error is just ValidationErrorExpired, we want to continue, as we can still
		// refresh the token if it's within the MaxRefresh time.
		// (see https://github.com/appleboy/gin-jwt/issues/176)
		validationErr, ok := err.(*jwt.ValidationError)
		if !ok || validationErr.Errors != jwt.ValidationErrorExpired {
			return nil, err
		}
	}

	claims := token.Claims.(*CustomClaims)

	if claims.ExpiresAt < jwt.TimeFunc().Add(-middleware.MaxRefresh).Unix() {
		return nil, ErrExpiredToken
	}

	return claims, nil
}

// ParseToken check and reture if token in the context
func (middleware *Middleware) ParseToken(c *gin.Context) (*jwt.Token, error) {
	token, err := middleware.jwtFromHeader(c)
	if err != nil {
		return nil, err
	}

	return jwt.ParseWithClaims(token, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(middleware.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if middleware.usingPublicKeyAlgo() {
			return middleware.pubKey, nil
		}

		// save token string if vaild
		c.Set("JWT_TOKEN", token)

		return middleware.SigningKey, nil
	})
}

func (middleware *Middleware) jwtFromHeader(c *gin.Context) (string, error) {
	authHeader := c.Request.Header.Get(middleware.JWTHeaderKey)

	if authHeader == "" {
		return "", errors.New("empty header")
	}

	if !strings.HasPrefix(authHeader, middleware.JWTHeaderPrefixWithSplitChar) {
		return "", errors.New("invalid header")
	}

	return authHeader[len(middleware.JWTHeaderPrefixWithSplitChar):], nil
}

func (middleware *Middleware) usingPublicKeyAlgo() bool {
	switch middleware.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}
