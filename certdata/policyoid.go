package certdata

// Source GlobalSign CP and Cabforum BR
// https://www.globalsign.com/en/repository/GlobalSign_CP_v5.3.pdf
var polOidType = make(map[string]string)

// TODO: Can we handle this differently, we might want to use a constant here?
func init() {
	// Extended Validation
	polOidType["1.3.6.1.4.1.4146.1.1"] = "EV" // Extended Validation Certificates Policy – SSL
	polOidType["1.3.6.1.4.1.4146.1.2"] = "CS" // Extended Validation Certificates Policy – Code Signing

	// Domain Validation
	polOidType["1.3.6.1.4.1.4146.1.10"] = "DV"    // Domain Validation Certificates Policy
	polOidType["1.3.6.1.4.1.4146.1.10.10"] = "DV" // Domain Validation Certificates Policy – AlphaSSL

	// Organization Validation
	polOidType["1.3.6.1.4.1.4146.1.20"] = "OV" // Organization Validation Certificates Policy
	polOidType["1.3.6.1.4.1.4146.1.21"] = "-"  // Untrusted OneClickSSL Test Certificate (not in cp)

	// Intranet Validation
	polOidType["1.3.6.1.4.1.4146.1.25"] = "IN" // IntranetSSL Validation Certificates Policy

	// Time Stamping
	polOidType["1.3.6.1.4.1.4146.1.30"] = "TS" // Time Stamping Certificates Policy
	polOidType["1.3.6.1.4.1.4146.1.31"] = "TS" // Time Stamping Certificates Policy – AATL

	// Client Certificates
	polOidType["1.3.6.1.4.1.4146.1.40"] = "PS"    // Client Certificates Policy (Generic)
	polOidType["1.3.6.1.4.1.4146.1.40.10"] = "PS" // Client Certificates Policy (ePKI – Enterprise PKI)
	polOidType["1.3.6.1.4.1.4146.1.40.20"] = "PS" // Client Certificates Policy (JCAN – Japan CA Network)
	polOidType["1.3.6.1.4.1.4146.1.40.30"] = "PS" // Client Certificates Policy (AATL)
	polOidType["1.3.6.1.4.1.4146.1.40.40"] = "PS" // Client Certificates Policy (ePKI for private CAs)

	// Code Signing
	polOidType["1.3.6.1.4.1.4146.1.50"] = "CS" // Code Signing Certificates Policy

	// CA Chaining and Cross Signing
	polOidType["1.3.6.1.4.1.4146.1.60"] = "CA"   // CA Chaining Policy – Trusted Root and Hosted Root
	polOidType["1.3.6.1.4.1.4146.1.60.1"] = "CA" // CA Chaining Policy – Trusted Root (Baseline Requirements Compatible)

	// Others
	/*polOidType["1.3.6.1.4.1.4146.1.80"] = "XX" // Retail Industry Electronic Data Interchange Client Certificate Policy
	polOidType["1.3.6.1.4.1.4146.1.81"] = "XX" // Retail Industry Electronic Data Interchange Server Certificate Policy
	polOidType["1.3.6.1.4.1.4146.1.90"] = "XX" // Trusted Root TPM Policy
	polOidType["1.3.6.1.4.1.4146.1.95"] = "XX" // Online Certificate Status Protocol Policy
	polOidType["1.3.6.1.4.1.4146.1.70"] = "XX" // High Volume CA Policy
	polOidType["1.3.6.1.4.1.4146.1.26"] = "XX" // Test Certificate Policy (Should not be trusted)

	// In addition to these identifiers, all Certificates that comply with the NAESB Business
	// Practice Standards will include one of the following additional identifiers:-
	polOidType["2.16.840.1.114505.1.12.1.2"] = "XX" // NAESB Rudimentary Assurance
	polOidType["2.16.840.1.114505.1.12.2.2"] = "XX" // NAESB Basic Assurance
	polOidType["2.16.840.1.114505.1.12.3.2"] = "XX" // NAESB Medium Assurance
	polOidType["2.16.840.1.114505.1.12.4.2"] = "XX" // NAESB High Assurance
	*/
	// In addition to these identifiers, all Certificates that comply with the Baseline
	// Requirements will include the following additional identifiers:-
	polOidType["2.23.140.1.1"] = "EV" // Extended Validation Certificate Policy
	//polOidType["2.23.140.1.2"] = "" // BR Compliance Certificate Policy
	polOidType["2.23.140.1.3"] = "EVCS" // Extended Validation Code Signing Certificates Policy
	polOidType["2.23.140.1.4"] = "CS"   // BR Compliance Code Signing Certificates Policy

	polOidType["2.23.140.1.2.1"] = "DV" // Domain Validation Certificates Policy
	polOidType["2.23.140.1.2.2"] = "OV" // Organization Validation Certificates Policy
	polOidType["2.23.140.1.2.3"] = "IV" // Individual Validation Certificates Policy

	polOidType["1.2.840.113583.1.2.1"] = "PS" // Adobe Certificate Policy Attribute Object Identifier (PDF)
	polOidType["1.2.840.113583.1.2.2"] = "PS" // Test Adobe Certificate Policy Attribute Object Identifier

	polOidType["1.3.6.1.4.1.4146.1.40.30.2"] = "PS" // AATL Adobe Certificate Policy Attribute Object Identifier
	polOidType["1.2.392.200063.30.5300"] = "PS"     // JCAN

}
