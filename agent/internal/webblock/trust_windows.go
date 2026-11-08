//go:build windows

package webblock

import (
	"crypto/x509"
	"errors"
	"log"
	"strings"
	"syscall"
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
// returns true to delete the one it was given. A deletion refused with access
// denied (a group-policy managed physical store) is logged and skipped.
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
		if ctx == nil {
			if err != nil && !errors.Is(err, syscall.Errno(windows.CRYPT_E_NOT_FOUND)) {
				return err
			}
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
			if derr := windows.CertDeleteCertificateFromStore(dup); derr != nil {
				if errors.Is(derr, windows.ERROR_ACCESS_DENIED) {
					log.Printf("webblock: cannot delete %q from the ROOT store: %v", c.Subject.CommonName, derr)
				} else if firstErr == nil {
					firstErr = derr
				}
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
	err := forEachOurs(func(c *x509.Certificate) bool {
		if fingerprintOf(c.Raw) == fingerprint {
			found = true
		}
		return false
	})
	return err == nil && found
}
