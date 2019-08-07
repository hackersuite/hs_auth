package models

type Error struct {
	Status int   `json:"status"`
	Err    error `json:"error"`
}
