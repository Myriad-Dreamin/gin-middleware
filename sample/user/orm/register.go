package orm

import (
	"log"

	"github.com/go-xorm/xorm"
)

// must register
var x *xorm.Engine

func GetEngine() *xorm.Engine {
	return x
}

// RegisterEngine to store objects
func RegisterEngine(y *xorm.Engine) {
	x = y

	if err := x.Sync(new(User)); err != nil {
		log.Fatal("Syn Error: User:", err)
	}

}
