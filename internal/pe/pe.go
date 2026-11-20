// Package pe inspects UEFI PE/COFF executables: machine type, SBAT metadata
// and Authenticode signatures.
//
// For each signature it recomputes the Authenticode image digest and checks
// it against the signed digest, and verifies the PKCS#7 signer's signature
// with the embedded signer certificate. It does NOT decide whether a machine
// will trust the binary — that depends on the firmware's db/dbx/MOK state and
// is enforced by the firmware and shim at boot. The reported issuer chain
// tells an administrator which trust anchor the binary needs.
package pe

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
)

// Info describes an EFI executable.
type Info struct {
	Machine    string      `json:"machine"`
	SBAT       string      `json:"sbat,omitempty"`
	Signatures []Signature `json:"signatures"`
	IsShim     bool        `json:"is_shim"`
	IsGRUB     bool        `json:"is_grub"`
	// GRUBPrefixes are "/EFI/<vendor>" strings embedded in a GRUB image,
	// i.e. where that GRUB will look for its configuration.
	GRUBPrefixes []string `json:"grub_prefixes,omitempty"`
}

// Signature is one Authenticode signature.
type Signature struct {
	Signer      string   `json:"signer"`
	Chain       []string `json:"chain"` // signer first, then issuers found in the bag
	DigestAlg   string   `json:"digest_alg"`
	DigestValid bool     `json:"digest_valid"`
	SignerValid bool     `json:"signer_valid"`
	Nested      bool     `json:"nested,omitempty"`
	Error       string   `json:"error,omitempty"`
	TrustAnchor string   `json:"trust_anchor"`
}

// Valid reports whether both the image digest and the signer signature check out.
func (s Signature) Valid() bool { return s.DigestValid && s.SignerValid && s.Error == "" }

// Signed reports whether at least one signature is cryptographically intact.
func (i *Info) Signed() bool {
	for _, s := range i.Signatures {
		if s.Valid() {
			return true
		}
	}
	return false
}

// Anchors lists the distinct trust anchors of the valid signatures.
func (i *Info) Anchors() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range i.Signatures {
		if s.Valid() && !seen[s.TrustAnchor] {
			seen[s.TrustAnchor] = true
			out = append(out, s.TrustAnchor)
		}
	}
	return out
}

type section struct {
	name    string
	rawOff  uint32
	rawSize uint32
}

type image struct {
	data        []byte
	checksumOff int
	certDirOff  int
	certOff     uint32
	certSize    uint32
	headersEnd  uint32
	sections    []section
}

func parse(data []byte) (*image, string, error) {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return nil, "", errors.New("not a PE image (no MZ header)")
	}
	peOff := int(binary.LittleEndian.Uint32(data[0x3C:]))
	if peOff < 0 || peOff+24 > len(data) || string(data[peOff:peOff+4]) != "PE\x00\x00" {
		return nil, "", errors.New("not a PE image (no PE signature)")
	}
	coff := peOff + 4
	machine := binary.LittleEndian.Uint16(data[coff:])
	nsec := int(binary.LittleEndian.Uint16(data[coff+2:]))
	ohSize := int(binary.LittleEndian.Uint16(data[coff+16:]))
	oh := coff + 20
	if oh+ohSize > len(data) || ohSize < 96 {
		return nil, "", errors.New("truncated optional header")
	}
	im := &image{data: data, checksumOff: oh + 64}
	var ddOff, nRVA int
	switch binary.LittleEndian.Uint16(data[oh:]) {
	case 0x10b:
		ddOff, nRVA = oh+96, int(binary.LittleEndian.Uint32(data[oh+92:]))
	case 0x20b:
		ddOff, nRVA = oh+112, int(binary.LittleEndian.Uint32(data[oh+108:]))
	default:
		return nil, "", errors.New("unknown optional header magic")
	}
	im.headersEnd = binary.LittleEndian.Uint32(data[oh+60:])
	if nRVA > 4 && ddOff+5*8 <= oh+ohSize {
		im.certDirOff = ddOff + 4*8
		im.certOff = binary.LittleEndian.Uint32(data[im.certDirOff:])
		im.certSize = binary.LittleEndian.Uint32(data[im.certDirOff+4:])
	}
	st := oh + ohSize
	for i := 0; i < nsec; i++ {
		s := st + i*40
		if s+40 > len(data) {
			return nil, "", errors.New("truncated section table")
		}
		im.sections = append(im.sections, section{
			name:    strings.TrimRight(string(data[s:s+8]), "\x00"),
			rawSize: binary.LittleEndian.Uint32(data[s+16:]),
			rawOff:  binary.LittleEndian.Uint32(data[s+20:]),
		})
	}
	m := map[uint16]string{0x8664: "x64", 0x14c: "ia32", 0xaa64: "aa64", 0x1c2: "arm", 0x5064: "riscv64"}[machine]
	if m == "" {
		m = fmt.Sprintf("unknown(%#x)", machine)
	}
	return im, m, nil
}

// digest computes the Authenticode image hash (PE/COFF spec, "Calculating
// the PE Image Hash").
func (im *image) digest(h crypto.Hash) ([]byte, error) {
	if !h.Available() {
		return nil, errors.New("unsupported digest")
	}
	d := h.New()
	data := im.data
	end := int(im.headersEnd)
	if end > len(data) || im.certDirOff == 0 || end < im.certDirOff+8 {
		return nil, errors.New("malformed headers")
	}
	d.Write(data[:im.checksumOff])
	d.Write(data[im.checksumOff+4 : im.certDirOff])
	d.Write(data[im.certDirOff+8 : end])
	secs := append([]section(nil), im.sections...)
	sort.Slice(secs, func(i, j int) bool { return secs[i].rawOff < secs[j].rawOff })
	sum := uint64(end)
	for _, s := range secs {
		if s.rawSize == 0 {
			continue
		}
		a, b := uint64(s.rawOff), uint64(s.rawOff)+uint64(s.rawSize)
		if b > uint64(len(data)) {
			return nil, errors.New("section beyond end of file")
		}
		d.Write(data[a:b])
		sum += uint64(s.rawSize)
	}
	limit := uint64(len(data))
	if im.certSize > 0 {
		limit = uint64(im.certOff)
	}
	if sum < limit {
		d.Write(data[sum:limit])
	}
	return d.Sum(nil), nil
}

func (im *image) section(name string) []byte {
	for _, s := range im.sections {
		if s.name == name {
			a, b := int(s.rawOff), int(s.rawOff)+int(s.rawSize)
			if b <= len(im.data) {
				return im.data[a:b]
			}
		}
	}
	return nil
}

var prefixRE = regexp.MustCompile(`/EFI/[A-Za-z0-9._-]{1,32}\x00`)

// Inspect analyses an EFI executable held in memory.
func Inspect(data []byte) (*Info, error) {
	im, machine, err := parse(data)
	if err != nil {
		return nil, err
	}
	info := &Info{Machine: machine}
	if sb := im.section(".sbat"); sb != nil {
		info.SBAT = strings.TrimRight(string(bytes.TrimRight(sb, "\x00")), "\n")
	}
	lines := "\n" + info.SBAT
	info.IsShim = strings.Contains(lines, "\nshim,") || im.section(".vendor_cert") != nil
	info.IsGRUB = strings.Contains(lines, "\ngrub,")
	if info.IsGRUB {
		seen := map[string]bool{}
		for _, m := range prefixRE.FindAll(data, 32) {
			p := strings.TrimSuffix(string(m), "\x00")
			if !seen[strings.ToLower(p)] {
				seen[strings.ToLower(p)] = true
				info.GRUBPrefixes = append(info.GRUBPrefixes, p)
			}
		}
	}
	if im.certSize > 0 {
		a, b := uint64(im.certOff), uint64(im.certOff)+uint64(im.certSize)
		if b > uint64(len(data)) || a < uint64(im.headersEnd) {
			info.Signatures = append(info.Signatures, Signature{Error: "certificate table out of range"})
			return info, nil
		}
		tbl := data[a:b]
		for len(tbl) >= 8 {
			l := binary.LittleEndian.Uint32(tbl[0:])
			typ := binary.LittleEndian.Uint16(tbl[6:])
			if l < 8 || uint64(l) > uint64(len(tbl)) {
				break
			}
			if typ == 2 { // WIN_CERT_TYPE_PKCS_SIGNED_DATA
				info.Signatures = append(info.Signatures, verifyPKCS7(im, tbl[8:l], false)...)
			}
			adv := (int(l) + 7) &^ 7
			if adv >= len(tbl) {
				break
			}
			tbl = tbl[adv:]
		}
	}
	return info, nil
}

// ---- PKCS#7 / Authenticode ----

var (
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSpcIndirectData = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidMessageDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidNestedSig       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      contentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version         int
	IssuerAndSerial issuerAndSerial
	DigestAlgorithm pkix.AlgorithmIdentifier
	AuthAttrs       asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncAlg    pkix.AlgorithmIdentifier
	EncryptedDigest []byte
	UnauthAttrs     asn1.RawValue `asn1:"optional,tag:1"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type spcIndirectData struct {
	Data          asn1.RawValue
	MessageDigest struct {
		Alg    pkix.AlgorithmIdentifier
		Digest []byte
	}
}

func hashFor(oid asn1.ObjectIdentifier) (crypto.Hash, string) {
	switch oid.String() {
	case "1.3.14.3.2.26":
		return crypto.SHA1, "sha1"
	case "2.16.840.1.101.3.4.2.1":
		return crypto.SHA256, "sha256"
	case "2.16.840.1.101.3.4.2.2":
		return crypto.SHA384, "sha384"
	case "2.16.840.1.101.3.4.2.3":
		return crypto.SHA512, "sha512"
	}
	return 0, oid.String()
}

func commonName(rawName []byte) string {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(rawName, &rdn); err != nil {
		return "?"
	}
	var n pkix.Name
	n.FillFromRDNSequence(&rdn)
	if n.CommonName != "" {
		return n.CommonName
	}
	return n.String()
}

func parseAttrs(raw asn1.RawValue) []attribute {
	var out []attribute
	rest := raw.Bytes
	for len(rest) > 0 {
		var a attribute
		r, err := asn1.Unmarshal(rest, &a)
		if err != nil {
			break
		}
		out = append(out, a)
		rest = r
	}
	return out
}

func verifyPKCS7(im *image, der []byte, nested bool) []Signature {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil || !ci.ContentType.Equal(oidSignedData) {
		return []Signature{{Error: "malformed PKCS#7 signature", Nested: nested}}
	}
	// With an explicit tag, RawValue.Bytes holds the complete inner element.
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return []Signature{{Error: "malformed SignedData: " + err.Error(), Nested: nested}}
	}
	if !sd.ContentInfo.ContentType.Equal(oidSpcIndirectData) {
		return []Signature{{Error: "not an Authenticode signature", Nested: nested}}
	}
	var spcRaw asn1.RawValue
	if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &spcRaw); err != nil {
		return []Signature{{Error: "malformed SpcIndirectDataContent", Nested: nested}}
	}
	var spc spcIndirectData
	if _, err := asn1.Unmarshal(spcRaw.FullBytes, &spc); err != nil {
		return []Signature{{Error: "malformed SpcIndirectDataContent", Nested: nested}}
	}
	certs, _ := x509.ParseCertificates(sd.Certificates.Bytes)
	var out []Signature
	for _, si := range sd.SignerInfos {
		s := Signature{Nested: nested}
		h, name := hashFor(spc.MessageDigest.Alg.Algorithm)
		s.DigestAlg = name
		if h != 0 {
			if got, err := im.digest(h); err == nil {
				s.DigestValid = bytes.Equal(got, spc.MessageDigest.Digest)
			} else {
				s.Error = err.Error()
			}
		}
		var leaf *x509.Certificate
		for _, c := range certs {
			if bytes.Equal(c.RawIssuer, si.IssuerAndSerial.Issuer.FullBytes) && c.SerialNumber.Cmp(si.IssuerAndSerial.Serial) == 0 {
				leaf = c
			}
		}
		if leaf == nil {
			s.Error = "signer certificate not included"
			out = append(out, s)
			continue
		}
		s.Signer = leaf.Subject.CommonName
		s.Chain = []string{leaf.Subject.CommonName}
		cur := leaf
		for depth := 0; depth < 8; depth++ {
			var parent *x509.Certificate
			for _, c := range certs {
				if c != cur && bytes.Equal(c.RawSubject, cur.RawIssuer) {
					parent = c
				}
			}
			if parent == nil {
				s.Chain = append(s.Chain, commonName(cur.RawIssuer))
				break
			}
			s.Chain = append(s.Chain, parent.Subject.CommonName)
			if bytes.Equal(parent.RawSubject, parent.RawIssuer) {
				break
			}
			cur = parent
		}
		s.TrustAnchor = classify(s.Chain)

		sh, _ := hashFor(si.DigestAlgorithm.Algorithm)
		if sh == 0 {
			s.Error = "unsupported signer digest"
			out = append(out, s)
			continue
		}
		var signed []byte
		if len(si.AuthAttrs.FullBytes) > 0 {
			// messageDigest covers the SpcIndirectDataContent value without
			// its outer tag and length (an Authenticode quirk).
			md := sh.New()
			md.Write(spcRaw.Bytes)
			ok := false
			for _, a := range parseAttrs(si.AuthAttrs) {
				if a.Type.Equal(oidMessageDigest) {
					var v []byte
					if _, err := asn1.Unmarshal(a.Values.Bytes, &v); err == nil && bytes.Equal(v, md.Sum(nil)) {
						ok = true
					}
				}
			}
			if !ok {
				s.Error = "messageDigest attribute does not match signed content"
			}
			signed = append([]byte(nil), si.AuthAttrs.FullBytes...)
			signed[0] = 0x31 // re-tag [0] IMPLICIT as SET OF for verification
		} else {
			signed = spcRaw.Bytes
		}
		hh := sh.New()
		hh.Write(signed)
		digest := hh.Sum(nil)
		switch pub := leaf.PublicKey.(type) {
		case *rsa.PublicKey:
			s.SignerValid = rsa.VerifyPKCS1v15(pub, sh, digest, si.EncryptedDigest) == nil
		case *ecdsa.PublicKey:
			s.SignerValid = ecdsa.VerifyASN1(pub, digest, si.EncryptedDigest)
		default:
			s.Error = "unsupported signer key type"
		}
		out = append(out, s)
		for _, a := range parseAttrs(si.UnauthAttrs) {
			if a.Type.Equal(oidNestedSig) {
				rest := a.Values.Bytes
				for len(rest) > 0 {
					var rv asn1.RawValue
					r, err := asn1.Unmarshal(rest, &rv)
					if err != nil {
						break
					}
					out = append(out, verifyPKCS7(im, rv.FullBytes, true)...)
					rest = r
				}
			}
		}
	}
	return out
}

// classify names the db/MOK trust anchor a chain needs, from well-known
// Microsoft certificate names. Anything else is a vendor key, trusted only
// through that vendor's shim or an enrolled MOK.
func classify(chain []string) string {
	for _, n := range chain {
		switch n {
		case "Microsoft Corporation UEFI CA 2011":
			return "Microsoft UEFI CA 2011 (third-party)"
		case "Microsoft UEFI CA 2023":
			return "Microsoft UEFI CA 2023 (third-party)"
		case "Microsoft Option ROM UEFI CA 2023":
			return "Microsoft Option ROM UEFI CA 2023"
		case "Microsoft Windows Production PCA 2011":
			return "Microsoft Windows Production PCA 2011"
		case "Windows UEFI CA 2023":
			return "Windows UEFI CA 2023"
		}
	}
	if len(chain) > 0 {
		return "vendor key: " + chain[len(chain)-1]
	}
	return "unknown"
}
