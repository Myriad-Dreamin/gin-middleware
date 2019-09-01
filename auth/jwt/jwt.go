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
	// ErrMissingSecretKey indicates Secret key is required
	ErrMissingSecretKey = errors.New("secret key is required")

	// ErrForbidden when HTTP status 403 is given
	ErrForbidden = errors.New("you don't have permission to access this resource")

	// ErrMissingAuthenticatorFunc indicates Authenticator is required
	ErrMissingAuthenticatorFunc = errors.New("ginJWTMiddleware.Authenticator func is undefined")

	// ErrMissingLoginValues indicates a user tried to authenticate without username or password
	ErrMissingLoginValues = errors.New("missing Username or Password")

	// ErrFailedAuthentication indicates authentication failed, could be faulty username or password
	ErrFailedAuthentication = errors.New("incorrect Username or Password")

	// ErrFailedTokenCreation indicates Middleware Token failed to create, reason unknown
	ErrFailedTokenCreation = errors.New("failed to create Middleware Token")

	// ErrExpiredToken indicates Middleware token has expired. Can't refresh.
	ErrExpiredToken = errors.New("token is expired")

	// ErrEmptyAuthHeader can be thrown if authing with a HTTP header, the Auth header needs to be set
	ErrEmptyAuthHeader = errors.New("auth header is empty")

	// ErrMissingExpField missing exp field in token
	ErrMissingExpField = errors.New("missing exp field")

	// ErrWrongFormatOfExp field must be float64 format
	ErrWrongFormatOfExp = errors.New("exp must be float64 format")

	// ErrInvalidAuthHeader indicates auth header is invalid, could for example have the wrong Realm name
	ErrInvalidAuthHeader = errors.New("auth header is invalid")

	// ErrEmptyQueryToken can be thrown if authing with URL Query, the query token variable is empty
	ErrEmptyQueryToken = errors.New("query token is empty")

	// ErrEmptyCookieToken can be thrown if authing with a cookie, the token cokie is empty
	ErrEmptyCookieToken = errors.New("cookie token is empty")

	// ErrEmptyParamToken can be thrown if authing with parameter in path, the parameter in path is empty
	ErrEmptyParamToken = errors.New("parameter token is empty")

	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid, needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

	// ErrNoPrivKeyFile indicates that the given private key is unreadable
	ErrNoPrivKeyFile = errors.New("private key file unreadable")

	// ErrNoPubKeyFile indicates that the given public key is unreadable
	ErrNoPubKeyFile = errors.New("public key file unreadable")

	// ErrInvalidPrivKey indicates that the given private key is invalid
	ErrInvalidPrivKey = errors.New("private key invalid")

	// ErrInvalidPubKey indicates the the given public key is invalid
	ErrInvalidPubKey = errors.New("public key invalid")
)

// Middleware 签名结构
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

// 载荷，可以加一些自己需要的信息
type CustomClaims struct {
	ID int `json:"id"`
	jwt.StandardClaims
}

// 新建一个jwt实例
func NewMiddleWare() *Middleware {
	return &Middleware{
		SigningAlgorithm:             "HS256",
		JWTHeaderKey:                 "Authorization",
		JWTHeaderPrefixWithSplitChar: "Bearer ",
		SigningKey:                   []byte(GetSignKey()),
	}
}

// Authorize 中间件，检查token
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
		// 继续交由下一个路由处理,并将解析出的信息传递下去
		c.Set("claims", claims)

		// todo: authorize identity

	}
}

// 一些常量
var (
	TokenExpired     error  = errors.New("Token is expired")
	TokenNotValidYet error  = errors.New("Token not active yet")
	TokenMalformed   error  = errors.New("That's not even a token")
	TokenInvalid     error  = errors.New("Couldn't handle this token:")
	SignKey          string = "Myriad-Dreamin"
)

// 获取signKey
func GetSignKey() string {
	return SignKey
}

// 这是SignKey
func SetSignKey(key string) string {
	SignKey = key
	return SignKey
}

// CreateToken 生成一个token
func (middleware *Middleware) CreateToken(claims CustomClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(middleware.SigningKey)
}

// 解析Tokne
func (middleware *Middleware) ParseClaim(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return middleware.SigningKey, nil
	})
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, TokenMalformed
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				// Token is expired
				return nil, TokenExpired
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return nil, TokenNotValidYet
			} else {
				return nil, TokenInvalid
			}
		}
	}
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, TokenInvalid
}

// 更新token
func (middleware *Middleware) RefreshToken(c *gin.Context) (string, error) {
	claims, err := middleware.CheckIfTokenExpire(c)
	if err != nil {
		return "", err
	}
	claims.StandardClaims.ExpiresAt = jwt.TimeFunc().Add(1 * time.Hour).Unix()
	return middleware.CreateToken(*claims)
}

// CheckIfTokenExpire check if token expire
func (mw *Middleware) CheckIfTokenExpire(c *gin.Context) (*CustomClaims, error) {
	token, err := mw.ParseToken(c)

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

	if claims.ExpiresAt < jwt.TimeFunc().Add(-mw.MaxRefresh).Unix() {
		return nil, ErrExpiredToken
	}

	return claims, nil
}

func (mw *Middleware) ParseToken(c *gin.Context) (*jwt.Token, error) {
	token, err := mw.jwtFromHeader(c)
	if err != nil {
		return nil, err
	}

	return jwt.ParseWithClaims(token, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}

		// save token string if vaild
		c.Set("JWT_TOKEN", token)

		return mw.SigningKey, nil
	})
}

func (mw *Middleware) jwtFromHeader(c *gin.Context) (string, error) {
	authHeader := c.Request.Header.Get(mw.JWTHeaderKey)

	if authHeader == "" {
		return "", errors.New("empty header")
	}

	if !strings.HasPrefix(authHeader, mw.JWTHeaderPrefixWithSplitChar) {
		return "", errors.New("invalid header")
	}

	return authHeader[len(mw.JWTHeaderPrefixWithSplitChar):], nil
}

// GenerateToken with expexpire time
func GenerateToken(id int, expireSecond int64) (string, error) {
	return (&Middleware{
		SigningKey: []byte("Myriad-Dreamin"),
	}).CreateToken(CustomClaims{
		id,
		jwt.StandardClaims{
			NotBefore: int64(time.Now().Unix() - 10),
			ExpiresAt: int64(time.Now().Unix() + expireSecond),
			Issuer:    "Myriad-Dreamin",
		},
	})
}

func (mw *Middleware) usingPublicKeyAlgo() bool {
	switch mw.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}
