package client

type ResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (r *ResponseError) Error() string {
	return r.Message
}

func newResponseError(c int, m string) *ResponseError {
	return &ResponseError{
		Code:    c,
		Message: m,
	}
}
