package adapters

func init() {
	Register(NewHTTPProbe())
	Register(NewSecurityHeaders())
	Register(NewSubfinder())
	Register(NewDNSX())
	Register(NewNaabu())
	Register(NewHTTPX())
	Register(NewWhois())
	Register(NewWaybackURLs())
	Register(NewCrtSH())
	Register(NewNmap())
	Register(NewFFUF())
	Register(NewSQLMap())
	Register(NewDalfox())
}
