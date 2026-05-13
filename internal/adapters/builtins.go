package adapters

func init() {
	Register(NewHTTPProbe())
	Register(NewSecurityHeaders())
}
