package main

const (
	CodeOK int = iota
	CodeBindError
	CodeInsertError
	CodeUserIDMissing
	CodeUserWrongPassword
	CodeNotFound

	CodeAuthGenerateTokenError
)
