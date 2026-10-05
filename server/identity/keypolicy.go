package identity

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// The App Attest leaf's three undocumented extensions. Their layout was read
// off a real macOS 27 attestation (testdata/appattest-macos.json):
//
//   - .8.5, the key's attributes: SEQUENCE of [n] EXPLICIT values, [1204]
//     being the App ID the key belongs to.
//   - .8.6, the key's access control: [3] EXPLICIT OCTET STRING wrapping
//     SEQUENCE { UTF8String protection, SEQUENCE OF SEQUENCE { UTF8String
//     operation, [n] constraint, SEQUENCE { [n] parameter … } } }, the
//     SEP's ACL for the key.
//   - .8.7, the attesting device's software: [1400] OS version, [1403]
//     build, [1026] platform, and firmware versions.
var (
	oidAppAttestKeyAttributes = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 5}
	oidAppAttestKeyACL        = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 6}
	oidAppAttestDevice        = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 7}
)

// Context tags inside .8.5 and .8.7 whose meaning is known.
const (
	tagKeyAppID    = 1204
	tagDeviceOS    = 1400
	tagDeviceBuild = 1403
	tagPlatform    = 1026
)

// ACLSign is the ACL operation that signs with the key, and ACLSecureBoot
// the constraint macOS puts on it for App Attest keys: the SEP checks the
// boot policy (Full Security, SIP on) before it signs. devicecheckd logs
// the same ACL as `osgn(csec(pslvl(1)))`, and on a Reduced Security Mac
// the signature fails with "Unexpected ACM requirement: 23".
const (
	ACLSign       = "osgn"
	ACLSecureBoot = "rsec"
)

// KeyPolicy is what the attested key's certificate says about the key and
// the Mac that made it. It is stored with the install as JSON.
type KeyPolicy struct {
	AppID      string `json:"app_id,omitempty"`
	OS         string `json:"os,omitempty"`
	Build      string `json:"build,omitempty"`
	Platform   string `json:"platform,omitempty"`
	Protection string `json:"protection,omitempty"`
	// ACL maps each operation to its constraint: "true" for allowed, or a
	// requirement with its parameters, such as "rsec([6]=1)".
	ACL map[string]string `json:"acl,omitempty"`
	// SignNeedsSecureBoot is osgn's constraint being rsec: the key signs
	// only while the Mac runs Full Security with SIP on.
	SignNeedsSecureBoot bool `json:"sign_needs_secure_boot"`
	// Attributes and Device are .8.5 and .8.7 in full, tag → value.
	Attributes map[string]string `json:"attributes,omitempty"`
	Device     map[string]string `json:"device,omitempty"`
}

// summary is the policy in a few words for the admin's tables.
func (p *KeyPolicy) Summary() string {
	switch {
	case p == nil:
		return ""
	case p.SignNeedsSecureBoot:
		return "full security"
	default:
		return "osgn " + p.ACL[ACLSign]
	}
}

// aclText lists the ACL as op=constraint, sorted.
func (p *KeyPolicy) ACLText() string {
	ops := make([]string, 0, len(p.ACL))
	for op, constraint := range p.ACL {
		ops = append(ops, op+"="+constraint)
	}
	sort.Strings(ops)
	return strings.Join(ops, " ")
}

// ReadKeyPolicy decodes the leaf's policy extensions. A missing extension
// leaves its fields empty; a malformed one is an error.
func ReadKeyPolicy(leaf *x509.Certificate) (*KeyPolicy, error) {
	policy := &KeyPolicy{}
	for _, ext := range leaf.Extensions {
		var err error
		switch {
		case ext.Id.Equal(oidAppAttestKeyAttributes):
			policy.Attributes, err = taggedValues(ext.Value)
			policy.AppID = policy.Attributes[strconv.Itoa(tagKeyAppID)]
		case ext.Id.Equal(oidAppAttestDevice):
			policy.Device, err = taggedValues(ext.Value)
			policy.OS = policy.Device[strconv.Itoa(tagDeviceOS)]
			policy.Build = policy.Device[strconv.Itoa(tagDeviceBuild)]
			policy.Platform = policy.Device[strconv.Itoa(tagPlatform)]
		case ext.Id.Equal(oidAppAttestKeyACL):
			policy.Protection, policy.ACL, err = accessControl(ext.Value)
			policy.SignNeedsSecureBoot = strings.HasPrefix(policy.ACL[ACLSign], ACLSecureBoot)
		}
		if err != nil {
			return nil, fmt.Errorf("extension %v: %w", ext.Id, err)
		}
	}
	return policy, nil
}

// taggedValues reads SEQUENCE { [n] EXPLICIT value … } into n → value.
func taggedValues(der []byte) (map[string]string, error) {
	items, err := sequenceItems(der)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(items))
	for _, item := range items {
		if item.Class != asn1.ClassContextSpecific {
			return nil, fmt.Errorf("item with class %d", item.Class)
		}
		value, err := explicitValue(item)
		if err != nil {
			return nil, err
		}
		out[strconv.Itoa(item.Tag)] = value
	}
	return out, nil
}

// accessControl reads the ACL extension into its protection class and
// operation → constraint.
func accessControl(der []byte) (string, map[string]string, error) {
	var wrapper struct {
		ACL []byte `asn1:"tag:3,explicit"`
	}
	if rest, err := asn1.Unmarshal(der, &wrapper); err != nil || len(rest) != 0 {
		return "", nil, errors.New("ACL wrapper is malformed")
	}
	parts, err := sequenceItems(wrapper.ACL)
	if err != nil || len(parts) != 2 || parts[0].Tag != asn1.TagUTF8String {
		return "", nil, errors.New("ACL is not { protection, entries }")
	}
	entries, err := sequenceItems(parts[1].FullBytes)
	if err != nil {
		return "", nil, err
	}
	acl := make(map[string]string, len(entries))
	for _, entry := range entries {
		fields, err := sequenceItems(entry.FullBytes)
		if err != nil || len(fields) == 0 {
			return "", nil, errors.New("ACL entry is malformed")
		}
		name := ""
		if fields[0].Class == asn1.ClassUniversal && fields[0].Tag == asn1.TagUTF8String {
			name, fields = string(fields[0].Bytes), fields[1:]
		}
		constraint, err := aclConstraint(fields)
		if err != nil {
			return "", nil, err
		}
		if name == "" {
			name = "-"
		}
		acl[name] = constraint
	}
	return string(parts[0].Bytes), acl, nil
}

// aclConstraint renders an entry's constraint: a value, then any
// parameters as ([n]=value,…), so osgn's is "rsec([6]=1)".
func aclConstraint(fields []asn1.RawValue) (string, error) {
	out := ""
	for _, field := range fields {
		if field.Class == asn1.ClassUniversal && field.Tag == asn1.TagSequence {
			params, err := sequenceItems(field.FullBytes)
			if err != nil {
				return "", err
			}
			rendered := make([]string, 0, len(params))
			for _, param := range params {
				value, err := explicitValue(param)
				if err != nil {
					return "", err
				}
				rendered = append(rendered, fmt.Sprintf("[%d]=%s", param.Tag, value))
			}
			out += "(" + strings.Join(rendered, ",") + ")"
			continue
		}
		value, err := explicitValue(field)
		if err != nil {
			return "", err
		}
		out += value
	}
	return out, nil
}

func sequenceItems(der []byte) ([]asn1.RawValue, error) {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(der, &sequence)
	if err != nil || len(rest) != 0 || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return nil, errors.New("not a SEQUENCE")
	}
	var items []asn1.RawValue
	for body := sequence.Bytes; len(body) > 0; {
		var item asn1.RawValue
		if body, err = asn1.Unmarshal(body, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

// explicitValue renders the universal value inside an [n] EXPLICIT tag.
func explicitValue(tagged asn1.RawValue) (string, error) {
	if !tagged.IsCompound {
		return hex.EncodeToString(tagged.Bytes), nil
	}
	var inner asn1.RawValue
	if rest, err := asn1.Unmarshal(tagged.Bytes, &inner); err != nil || len(rest) != 0 {
		return "", fmt.Errorf("[%d] holds no single value", tagged.Tag)
	}
	switch inner.Tag {
	case asn1.TagBoolean:
		return strconv.FormatBool(len(inner.Bytes) == 1 && inner.Bytes[0] != 0), nil
	case asn1.TagInteger:
		var n *big.Int
		if _, err := asn1.Unmarshal(inner.FullBytes, &n); err != nil {
			return "", err
		}
		return n.String(), nil
	case asn1.TagOctetString, asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String:
		if printable(inner.Bytes) {
			return string(inner.Bytes), nil
		}
	}
	return hex.EncodeToString(inner.Bytes), nil
}

func printable(b []byte) bool {
	for _, r := range string(b) {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return len(b) > 0
}
