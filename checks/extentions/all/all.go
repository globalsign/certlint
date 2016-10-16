package all

import (
	// Import all default extentions
	_ "github.com/globalsign/certlint/checks/extentions/authorityinfoaccess"
	_ "github.com/globalsign/certlint/checks/extentions/authoritykeyid"
	_ "github.com/globalsign/certlint/checks/extentions/basicconstraints"
	_ "github.com/globalsign/certlint/checks/extentions/crldistributionpoints"
	_ "github.com/globalsign/certlint/checks/extentions/ct"
	_ "github.com/globalsign/certlint/checks/extentions/extkeyusage"
	_ "github.com/globalsign/certlint/checks/extentions/keyusage"
	_ "github.com/globalsign/certlint/checks/extentions/nameconstraints"
	_ "github.com/globalsign/certlint/checks/extentions/policyidentifiers"
	_ "github.com/globalsign/certlint/checks/extentions/subjectaltname"
	_ "github.com/globalsign/certlint/checks/extentions/subjectkeyid"
)
