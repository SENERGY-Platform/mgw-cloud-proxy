package cert

type Config struct {
	WorkDirPath         string `json:"work_dir_path" env_var:"CERT_HDL_WORKDIR"`
	TargetDirPath       string `json:"target_dir_path" env_var:"CERT_HDL_TARGET_DIR"`
	DummyDirPath        string `json:"dummy_dir_path" env_var:"CERT_HDL_DUMMY_DIR"`
	PrivateKeyAlgorithm string `json:"private_key_algorithm" env_var:"PRIVATE_KEY_ALGO"`
}
