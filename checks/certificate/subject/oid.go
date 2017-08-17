package subject

import "encoding/asn1"

// http://www.alvestrand.no/objectid/2.5.4.html
var (
	objectClass                 = asn1.ObjectIdentifier{2, 5, 4, 0}
	aliasedEntryName            = asn1.ObjectIdentifier{2, 5, 4, 1}
	knowldgeinformation         = asn1.ObjectIdentifier{2, 5, 4, 2}
	commonName                  = asn1.ObjectIdentifier{2, 5, 4, 3}
	surname                     = asn1.ObjectIdentifier{2, 5, 4, 4}
	serialNumber                = asn1.ObjectIdentifier{2, 5, 4, 5}
	countryName                 = asn1.ObjectIdentifier{2, 5, 4, 6}
	localityName                = asn1.ObjectIdentifier{2, 5, 4, 7}
	stateOrProvinceName         = asn1.ObjectIdentifier{2, 5, 4, 8}
	streetAddress               = asn1.ObjectIdentifier{2, 5, 4, 9}
	organizationName            = asn1.ObjectIdentifier{2, 5, 4, 10}
	organizationalUnitName      = asn1.ObjectIdentifier{2, 5, 4, 11}
	title                       = asn1.ObjectIdentifier{2, 5, 4, 12}
	description                 = asn1.ObjectIdentifier{2, 5, 4, 13}
	searchGuide                 = asn1.ObjectIdentifier{2, 5, 4, 14}
	businessCategory            = asn1.ObjectIdentifier{2, 5, 4, 15}
	postalAddress               = asn1.ObjectIdentifier{2, 5, 4, 16}
	postalCode                  = asn1.ObjectIdentifier{2, 5, 4, 17}
	postOfficeBox               = asn1.ObjectIdentifier{2, 5, 4, 18}
	physicalDeliveryOfficeName  = asn1.ObjectIdentifier{2, 5, 4, 19}
	telephoneNumber             = asn1.ObjectIdentifier{2, 5, 4, 20}
	telexNumber                 = asn1.ObjectIdentifier{2, 5, 4, 21}
	teletexTerminalIdentifier   = asn1.ObjectIdentifier{2, 5, 4, 22}
	facsimileTelephoneNumber    = asn1.ObjectIdentifier{2, 5, 4, 23}
	x121Address                 = asn1.ObjectIdentifier{2, 5, 4, 24}
	internationalISDNNumber     = asn1.ObjectIdentifier{2, 5, 4, 25}
	registeredAddress           = asn1.ObjectIdentifier{2, 5, 4, 26}
	destinationIndicator        = asn1.ObjectIdentifier{2, 5, 4, 27}
	preferredDeliveryMethod     = asn1.ObjectIdentifier{2, 5, 4, 28}
	presentationAddress         = asn1.ObjectIdentifier{2, 5, 4, 29}
	supportedApplicationContext = asn1.ObjectIdentifier{2, 5, 4, 30}
	member                      = asn1.ObjectIdentifier{2, 5, 4, 31}
	owner                       = asn1.ObjectIdentifier{2, 5, 4, 32}
	roleOccupant                = asn1.ObjectIdentifier{2, 5, 4, 33}
	seeAlso                     = asn1.ObjectIdentifier{2, 5, 4, 34}
	userPassword                = asn1.ObjectIdentifier{2, 5, 4, 35}
	userCertificate             = asn1.ObjectIdentifier{2, 5, 4, 36}
	cACertificate               = asn1.ObjectIdentifier{2, 5, 4, 37}
	authorityRevocationList     = asn1.ObjectIdentifier{2, 5, 4, 38}
	certificateRevocationList   = asn1.ObjectIdentifier{2, 5, 4, 39}
	crossCertificatePair        = asn1.ObjectIdentifier{2, 5, 4, 40}
	name                        = asn1.ObjectIdentifier{2, 5, 4, 41}
	givenName                   = asn1.ObjectIdentifier{2, 5, 4, 42}
	initials                    = asn1.ObjectIdentifier{2, 5, 4, 43}
	generationQualifier         = asn1.ObjectIdentifier{2, 5, 4, 44}
	uniqueIdentifier            = asn1.ObjectIdentifier{2, 5, 4, 45}
	dnQualifier                 = asn1.ObjectIdentifier{2, 5, 4, 46}
	enhancedSearchGuide         = asn1.ObjectIdentifier{2, 5, 4, 47}
	protocolInformation         = asn1.ObjectIdentifier{2, 5, 4, 48}
	distinguishedName           = asn1.ObjectIdentifier{2, 5, 4, 49}
	uniqueMember                = asn1.ObjectIdentifier{2, 5, 4, 50}
	houseIdentifier             = asn1.ObjectIdentifier{2, 5, 4, 51}
	supportedAlgorithms         = asn1.ObjectIdentifier{2, 5, 4, 52}
	deltaRevocationList         = asn1.ObjectIdentifier{2, 5, 4, 53}
	attributeCertificate        = asn1.ObjectIdentifier{2, 5, 4, 58}
	pseudonym                   = asn1.ObjectIdentifier{2, 5, 4, 65}

	emailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	jurisdictionLocalityName        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1}
	jurisdictionStateOrProvinceName = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2}
	jurisdictionCountryName         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}
)
