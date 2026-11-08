//go:build windows

package webblock

import (
	"crypto/x509"
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openRootStore() (windows.Handle, error) {
	return windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("ROOT"))))
}

func installTrust(der []byte, fingerprint string) error {
	if len(der) == 0 {
		return errors.New("empty certificate")
	}
	store, err := openRootStore()
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	ctx, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, &der[0], uint32(len(der)))
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(ctx)
	return windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil)
}

// forEachOurs visits every ADSIEM certificate in the machine ROOT store; fn
// returns true to delete the one it was given.
func forEachOurs(fn func(c *x509.Certificate) (del bool)) error {
	store, err := openRootStore()
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	var prev *windows.CertContext
	var firstErr error
	for {
		// The enumeration frees prev; deleting works on a duplicate.
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil || ctx == nil {
			break
		}
		prev = ctx
		der := append([]byte(nil), unsafe.Slice(ctx.EncodedCert, ctx.Length)...)
		c, perr := x509.ParseCertificate(der)
		if perr != nil || !strings.HasPrefix(c.Subject.CommonName, caSubjectPrefix) {
			continue
		}
		if fn(c) {
			dup := windows.CertDuplicateCertificateContext(ctx)
			if derr := windows.CertDeleteCertificateFromStore(dup); derr != nil && firstErr == nil {
				firstErr = derr
			}
		}
	}
	return firstErr
}

func removeTrust(string) error {
	return forEachOurs(func(*x509.Certificate) bool { return true })
}

func trustInstalled(fingerprint string) bool {
	found := false
	forEachOurs(func(c *x509.Certificate) bool {
		if fingerprintOf(c.Raw) == fingerprint {
			found = true
		}
		return false
	})
	return found
}

// protectKeyFile restricts the file to SYSTEM and Administrators with a
// protected (non-inherited) DACL.
func protectKeyFile(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
