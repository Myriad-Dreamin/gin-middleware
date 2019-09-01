package orm

import (
	"errors"

	"github.com/go-xorm/xorm"
)

// User example
type User struct {
	ID int `xorm:"not null pk unique autoincr 'id'"`

	Name     string `form:"name" json:"name" xorm:"unique 'name'" binding:"required"`
	Password string `form:"password" json:"password" xorm:"'password'" binding:"required"`
	Exp      int    `xorm:"'exp'"`

	Email  string `xorm:"unique 'email'" form:"email" json:"email"`
	Phone  string `xorm:"unique 'phone'" form:"phone" json:"phone"`
	School string `xorm:"'school'" form:"school" json:"school"`

	SolvedProblems int `xorm:"'solved_problems'"`
}

// TableName return the table name
func (obj *User) TableName() string {
	return "users"
}

// GetSliceWithPredict return the slice of User with reserving the space of n User
func (obj *User) GetSliceWithPredict(n int) interface{} {
	return make([]User, 0, n)
}

// GetSlice return the slice of User
func (obj *User) GetSlice() interface{} {
	return make([]User, 0)
}

// Insert into Engine
func (obj *User) Insert() (int64, error) {
	return x.Insert(obj)
}

// Insert Unique
func (obj *User) InsertWithDefault() (int64, error) {
	var mapobj = make(map[string]interface{})
	if len(obj.Name) != 0 {
		mapobj["name"] = obj.Name
	} else {
		return 0, errors.New("name missing")
	}

	if len(obj.Password) != 0 {
		mapobj["password"] = obj.Password
	}

	if obj.Exp != 0 {
		mapobj["exp"] = obj.Exp
	}

	if len(obj.Email) != 0 {
		mapobj["email"] = obj.Email
	}

	if len(obj.Phone) != 0 {
		mapobj["phone"] = obj.Phone
	}

	if len(obj.School) != 0 {
		mapobj["school"] = obj.School
	}

	if obj.SolvedProblems != 0 {
		mapobj["solved_problems"] = obj.SolvedProblems
	}
	affected, err := x.Table(obj.TableName()).Insert(mapobj)
	if affected == 0 || err != nil {
		return affected, err
	}
	has, err := x.Table(obj.TableName()).Cols("id").Get(obj)
	if !has {
		return 0, errors.New("insert missing")
	}
	return affected, err
}

// Delete from Engine
func (obj *User) Delete() (int64, error) {
	return x.ID(obj.ID).Delete(obj)
}

// Update to Engine
func (obj *User) Update() (int64, error) {
	return x.ID(obj.ID).Update(obj)
}

// UpdateAll to Engine
func (obj *User) UpdateAll() (int64, error) {
	return x.ID(obj.ID).AllCols().Update(obj)
}

// Query from Engine
func (obj *User) Query() (bool, error) {
	return x.Get(obj)
}

// UserX Extend the Engine operation
type UserX struct {
}

func NewUserX() (*UserX, error) {
	return new(UserX), nil
}

// UserXSession Extend the Engine operation
type UserXSession xorm.Session

// Query return the user with Property property
func (objx *UserX) Query(property int) (*User, error) {
	obj := new(User)
	obj.ID = property
	has, err := x.Get(obj)
	if has {
		return obj, nil
	}
	return nil, err
}

// QueryName return the user with Property property
func (objx *UserX) QueryName(property string) (*User, error) {
	obj := new(User)
	obj.Name = property
	has, err := x.Get(obj)
	if has {
		return obj, nil
	}
	return nil, err
}

// QueryEmail return the user with Property property
func (objx *UserX) QueryEmail(property string) (*User, error) {
	obj := new(User)
	obj.Email = property
	has, err := x.Get(obj)
	if has {
		return obj, nil
	}
	return nil, err
}

// QueryPhone return the user with Property property
func (objx *UserX) QueryPhone(property string) (*User, error) {
	obj := new(User)
	obj.Phone = property
	has, err := x.Get(obj)
	if has {
		return obj, nil
	}
	return nil, err
}

// Inserts many Users
func (objx *UserX) Inserts(objs []User) (int64, error) {
	return x.Insert(objs)
}

// Querys with conditions
func (objx *UserX) Querys(objs []User, conds ...interface{}) error {
	return x.Find(&objs, conds...)
}

// ColsQuerys with conditions with specifying columns
func (objx *UserX) ColsQuerys(objs []User, cols ...string) error {
	return x.Cols(cols...).Find(&objs)
}

// Where provIDes custom query condition.
func (objx *UserX) Where(query interface{}, args ...interface{}) *UserXSession {
	return (*UserXSession)(x.Where(query, args...))
}

// Where provIDes custom query condition.
func (objx *UserXSession) Where(query interface{}, args ...interface{}) *UserXSession {
	return (*UserXSession)(((*xorm.Session)(objx)).Where(query, args...))
}

// And provIDes custom query condition.
func (objx *UserXSession) And(query interface{}, args ...interface{}) *UserXSession {
	return (*UserXSession)(((*xorm.Session)(objx)).And(query, args...))
}

// Or provIDes custom query condition.
func (objx *UserXSession) Or(query interface{}, args ...interface{}) *UserXSession {
	return (*UserXSession)(((*xorm.Session)(objx)).Or(query, args...))
}

// ID provIDes custom query condition.
func (objx *UserXSession) ID(query interface{}) *UserXSession {
	return (*UserXSession)(((*xorm.Session)(objx)).ID(query))
}

// NotIn provIDes custom query condition.
func (objx *UserXSession) NotIn(query string, args ...interface{}) *UserXSession {
	return (*UserXSession)(((*xorm.Session)(objx)).NotIn(query, args...))
}

// In provIDes custom query condition.
func (objx *UserXSession) In(query string, args ...interface{}) *UserXSession {
	return (*UserXSession)(((*xorm.Session)(objx)).In(query, args...))
}

// Find retrieve records from table, condiBeans's non-empty fields
// are conditions. beans could be []Struct, []*Struct, map[int64]Struct
// map[int64]*Struct
func (objx *UserXSession) Find(conds ...interface{}) ([]User, error) {
	objs := make([]User, 0)
	err := ((*xorm.Session)(objx)).Find(objs, conds...)
	return objs, err
}
