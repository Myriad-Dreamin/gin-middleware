package orm

import (
	"github.com/go-xorm/xorm"
)

// Object example
type Object struct {
	ID int `xorm:"not null pk autoincr"`
}

// TableName return the table name
func (obj *Object) TableName() string {
	return "object_example"
}

// GetSliceWithPredict return the slice of object with reserving the space of n Object
func (obj *Object) GetSliceWithPredict(n int) interface{} {
	return make([]Object, 0, n)
}

// GetSlice return the slice of object
func (obj *Object) GetSlice() interface{} {
	return make([]Object, 0)
}

// Insert into Engine
func (obj *Object) Insert() (int64, error) {
	return x.Insert(obj)
}

// Delete from Engine
func (obj *Object) Delete() (int64, error) {
	return x.ID(obj.ID).Delete(obj)
}

// Update to Engine
func (obj *Object) Update() (int64, error) {
	return x.ID(obj.ID).Update(obj)
}

// Query from Engine
func (obj *Object) Query() (bool, error) {
	return x.Get(obj)
}

// Objector Extend the Engine operation
type Objector struct {
}

func NewObjector() (*Objector, error) {
	return new(Objector), nil
}

// ObjectorSession Extend the Engine operation
type ObjectorSession xorm.Session

// Query return the code with Property property
func (objx *Objector) Query(property int) (*Object, error) {
	obj := new(Object)
	obj.ID = property
	has, err := x.Get(obj)
	if has {
		return obj, nil
	}
	return nil, err
}

// Inserts many objects
func (objx *Objector) Inserts(objs []Object) (int64, error) {
	return x.Insert(objs)
}

// Querys with conditions
func (objx *Objector) Querys(objs []Object, conds ...interface{}) error {
	return x.Find(&objs, conds...)
}

// ColsQuerys with conditions with specifying columns
func (objx *Objector) ColsQuerys(objs []Object, cols ...string) error {
	return x.Cols(cols...).Find(&objs)
}

// Where provIDes custom query condition.
func (objx *Objector) Where(query interface{}, args ...interface{}) *ObjectorSession {
	return (*ObjectorSession)(x.Where(query, args...))
}

// Where provIDes custom query condition.
func (objx *ObjectorSession) Where(query interface{}, args ...interface{}) *ObjectorSession {
	return (*ObjectorSession)(((*xorm.Session)(objx)).Where(query, args...))
}

// And provIDes custom query condition.
func (objx *ObjectorSession) And(query interface{}, args ...interface{}) *ObjectorSession {
	return (*ObjectorSession)(((*xorm.Session)(objx)).And(query, args...))
}

// Or provIDes custom query condition.
func (objx *ObjectorSession) Or(query interface{}, args ...interface{}) *ObjectorSession {
	return (*ObjectorSession)(((*xorm.Session)(objx)).Or(query, args...))
}

// ID provIDes custom query condition.
func (objx *ObjectorSession) ID(query interface{}) *ObjectorSession {
	return (*ObjectorSession)(((*xorm.Session)(objx)).ID(query))
}

// NotIn provIDes custom query condition.
func (objx *ObjectorSession) NotIn(query string, args ...interface{}) *ObjectorSession {
	return (*ObjectorSession)(((*xorm.Session)(objx)).NotIn(query, args...))
}

// In provIDes custom query condition.
func (objx *ObjectorSession) In(query string, args ...interface{}) *ObjectorSession {
	return (*ObjectorSession)(((*xorm.Session)(objx)).In(query, args...))
}

// Find retrieve records from table, condiBeans's non-empty fields
// are conditions. beans could be []Struct, []*Struct, map[int64]Struct
// map[int64]*Struct
func (objx *ObjectorSession) Find(conds ...interface{}) ([]Object, error) {
	objs := make([]Object, 0)
	err := ((*xorm.Session)(objx)).Find(&objs, conds...)
	return objs, err
}
