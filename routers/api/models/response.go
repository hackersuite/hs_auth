package models

// Response is the basic model for an API response
type Response struct {
	Status int    `json:"status"`
	Err    string `json:"error"`
}
