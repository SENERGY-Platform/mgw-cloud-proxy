package listener

import "io/fs"

type Config struct {
	Path     string      `json:"path" env_var:"SOCKET_PATH"`
	UserID   int         `json:"user_id" env_var:"SOCKET_USER_ID"`
	GroupID  int         `json:"group_id" env_var:"SOCKET_GROUP_ID"`
	FileMode fs.FileMode `json:"file_mode" env_var:"SOCKET_FILE_MODE"`
}
