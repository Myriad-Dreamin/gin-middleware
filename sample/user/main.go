package main

import (
	"fmt"
	"os"

	"github.com/Myriad-Dreamin/core-oj/log"
	jwt "github.com/Myriad-Dreamin/gin-middleware/auth/jwt"
	morm "github.com/Myriad-Dreamin/gin-middleware/sample/user/orm"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/go-xorm/xorm"
)

type Server struct {
	engine *xorm.Engine
	logger log.TendermintLogger
}

func NewServer() (srv *Server, err error) {
	srv = new(Server)

	srv.logger, err = log.NewZapColorfulDevelopmentSugarLogger()
	if err != nil {
		return nil, err
	}

	return
}

func (srv *Server) prepareDatabase(driver, connection string) error {
	var err error

	srv.engine, err = xorm.NewEngine(driver, connection)
	if err != nil {
		srv.logger.Error("prepare failed", "error", err)
		return err
	}

	morm.RegisterEngine(srv.engine)

	srv.engine.ShowSQL(true)
	return nil
}

func (srv *Server) Close() error {
	return nil
}

func (srv *Server) Serve(port string) error {

	userx, err := morm.NewUserX()
	if err != nil {
		return err
	}

	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	userRouter := r.Group("/user")
	{
		var userService = NewUserService(userx, srv.logger)
		// userRouter.GET("/:id", userService.Get)
		// userRouter.GET("/:id/content", userService.GetContent)
		// userRouter.GET("/:id/result", userService.GetResult)
		userRouter.POST("/register", userService.Register)
		userRouter.POST("/login", userService.Login)
		// userRouter.PUT("/:id/updateform-runtimeid", userService.UpdateRuntimeID)
		// userRouter.DELETE("/:id", userService.Delete)
	}

	testRouter := r.Group("/api")
	{
		testRouter.GET("/auth", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"msg": "orzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			})
		})
		testRouter.Use(jwt.NewMiddleWare().Authorize())
		testRouter.GET("/authv2", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"msg": "orzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			})
		})
		testRouter.Group("/")
		testRouter.GET("/authv3", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"msg": "orzzzzzzzzzzzzzzzzzzzzzzzzz",
			})
		})
	}

	return r.Run(port)
}

func main() {
	var srv, err = NewServer()
	if err != nil {
		fmt.Println(err)
		return
	}
	err = srv.prepareDatabase("mysql", "coreoj-admin:123456@tcp(127.0.0.1:3306)/coreoj?charset=utf8")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() {
		err := srv.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()

	if err = srv.Serve(":23336"); err != nil {
		fmt.Println(err)
		return
	}
}
