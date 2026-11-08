//go:build windows

package ransomguard

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modcrypt32           = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = modcrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = modcrypt32.NewProc("CryptMsgClose")
)

const cmsgSignerCertInfoParam = 7 // CMSG_SIGNER_CERT_INFO_PARAM

// verifyMicrosoft reports whether path carries a valid embedded Authenticode
// signature (WinVerifyTrust, chain to a trusted root, no revocation check:
// the agent may be offline) whose signer certificate's subject is
// "Microsoft Corporation". The signer is the certificate the signature names
// (issuer and serial from the PKCS #7 signer info), not any certificate the
// file happens to carry. Catalog-signed files are not trusted.
func verifyMicrosoft(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	data := &windows.WinTrustData{
		Size:             uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:         windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_NONE,
		UnionChoice:      windows.WTD_CHOICE_FILE,
		StateAction:      windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
			FilePath: p,
		}),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verifyErr != nil {
		return false
	}
	return signerName(p) == "Microsoft Corporation"
}

// signerName is the simple display name of the certificate that signed the
// file's embedded signature, or "".
func signerName(path *uint16) string {
	var encoding, content, format uint32
	var store, msg windows.Handle
	if err := windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(path),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, windows.CERT_QUERY_FORMAT_FLAG_BINARY, 0,
		&encoding, &content, &format, &store, &msg, nil); err != nil {
		return ""
	}
	defer windows.CertCloseStore(store, 0)
	defer procCryptMsgClose.Call(uintptr(msg))
	var size uint32
	if r, _, _ := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerCertInfoParam, 0, 0, uintptr(unsafe.Pointer(&size))); r == 0 || size == 0 {
		return ""
	}
	buf := make([]uint64, (size+7)/8) // CERT_INFO with pointers into the buffer: 8-byte aligned
	if r, _, _ := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerCertInfoParam, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return ""
	}
	cert, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0,
		windows.CERT_FIND_SUBJECT_CERT, unsafe.Pointer(&buf[0]), nil)
	if err != nil || cert == nil {
		return ""
	}
	defer windows.CertFreeCertificateContext(cert)
	name := make([]uint16, 256)
	n := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &name[0], uint32(len(name)))
	if n <= 1 {
		return ""
	}
	return windows.UTF16ToString(name[:n])
}
