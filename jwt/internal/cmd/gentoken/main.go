package main

import (
	"bytes"
	"fmt"
	"go/format"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

func main() {
	if err := _main(); err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}
}

func _main() error {
	if err := generateToken(); err != nil {
		return errors.Wrap(err, `failed to generate token file`)
	}
	return nil
}

type tokenField struct {
	name      string
	typ       string
	key       string
	method    string
	comment   string
	isList    bool
	hasAccept bool
	noDeref   bool
	elemType  string
	jsonTag   string
}

func (t tokenField) UpperName() string {
	return strings.Title(t.name)
}

func (t tokenField) IsList() bool {
	return t.isList || strings.HasPrefix(t.typ, `[]`)
}

func (t tokenField) ListElem() string {
	if t.elemType != "" {
		return t.elemType
	}
	return strings.TrimPrefix(t.typ, `[]`)
}

func (t tokenField) IsPointer() bool {
	return strings.HasPrefix(t.typ, `*`)
}

func (t tokenField) PointerElem() string {
	return strings.TrimPrefix(t.typ, `*`)
}

var zerovals = map[string]string{
	`string`: `""`,
}

func zeroval(s string) string {
	if v, ok := zerovals[s]; ok {
		return v
	}
	return `nil`
}

func generateToken() error {
	var buf bytes.Buffer

	var fields = []tokenField{
		{
			name:      "Audience",
			method:    "GetAudience",
			typ:       "StringList",
			key:       "aud",
			comment:   `https://tools.ietf.org/html/rfc7519#section-4.1.3`,
			isList:    true,
			hasAccept: true,
			elemType:  `string`,
			jsonTag:   "`" + `json:"aud,omitempty"` + "`",
		},
		{
			name:      "Expiration",
			method:    "GetExpiration",
			typ:       "*NumericDate",
			key:       "exp",
			comment:   `https://tools.ietf.org/html/rfc7519#section-4.1.4`,
			hasAccept: true,
			noDeref:   true,
			jsonTag:   "`" + `json:"exp,omitempty"` + "`",
		},
		{
			name:      "IssuedAt",
			method:    "GetIssuedAt",
			typ:       "*NumericDate",
			key:       "iat",
			comment:   `https://tools.ietf.org/html/rfc7519#section-4.1.6`,
			hasAccept: true,
			noDeref:   true,
			jsonTag:   "`" + `json:"iat,omitempty"` + "`",
		},
		{
			name:    "Issuer",
			method:  "GetIssuer",
			typ:     "*string",
			key:     "iss",
			comment: `https://tools.ietf.org/html/rfc7519#section-4.1.1`,
			jsonTag: "`" + `json:"iss,omitempty"` + "`",
		},
		{
			name:    "JwtID",
			method:  "GetJwtID",
			typ:     "*string",
			key:     "jti",
			comment: `https://tools.ietf.org/html/rfc7519#section-4.1.7`,
			jsonTag: "`" + `json:"jti,omitempty"` + "`",
		},
		{
			name:      "NotBefore",
			method:    "GetNotBefore",
			typ:       "*NumericDate",
			key:       "nbf",
			comment:   `https://tools.ietf.org/html/rfc7519#section-4.1.5`,
			hasAccept: true,
			noDeref:   true,
			jsonTag:   "`" + `json:"nbf,omitempty"` + "`",
		},
		{
			name:    "Subject",
			method:  "GetSubject",
			typ:     "*string",
			key:     "sub",
			comment: `https://tools.ietf.org/html/rfc7519#section-4.1.2`,
			jsonTag: "`" + `json:"sub,omitempty"` + "`",
		},
		{
			name:    `PrivateClaims`,
			method:  "GetPrivateClaims",
			typ:     `map[string]interface{}`,
			key:     "privateClaims",
			comment: `https://tools.ietf.org/html/rfc7515#section-4.1.4`,
			jsonTag: "`" + `json:"privateClaims,omitempty"` + "`",
		},
	}

	fmt.Fprintf(&buf, "\n// This file is auto-generated. DO NOT EDIT")
	fmt.Fprintf(&buf, "\npackage jwt")
	fmt.Fprintf(&buf, "\n\nimport (")
	for _, pkg := range []string{"bytes", "encoding/json", "time", "github.com/pkg/errors"} {
		fmt.Fprintf(&buf, "\n%s", strconv.Quote(pkg))
	}
	fmt.Fprintf(&buf, "\n)") // end of import

	fmt.Fprintf(&buf, "\n\n// Key names for standard claims")
	fmt.Fprintf(&buf, "\nconst (")
	for _, field := range fields {
		fmt.Fprintf(&buf, "\n%sKey = %s", field.UpperName(), strconv.Quote(field.key))
	}
	fmt.Fprintf(&buf, "\n)") // end const

	fmt.Fprintf(&buf, "\n\n// Token represents a JWT token. The object has convenience accessors")
	fmt.Fprintf(&buf, "\n// to %d standard claims including ", len(fields))
	for i, field := range fields {
		fmt.Fprintf(&buf, "%s", strconv.Quote(field.key))
		switch {
		case i < len(fields)-2:
			fmt.Fprintf(&buf, ", ")
		case i == len(fields)-2:
			fmt.Fprintf(&buf, " and ")
		}
	}
	fmt.Fprintf(&buf, "\n// which are type-aware (to an extent). Other claims may be accessed via the `Get`/`Set`")
	fmt.Fprintf(&buf, "\n// methods but their types are not taken into consideration at all. If you have non-standard")
	fmt.Fprintf(&buf, "\n// claims that you must frequently access, consider wrapping the token in a wrapper")
	fmt.Fprintf(&buf, "\n// by embedding the jwt.Token type in it")
	fmt.Fprintf(&buf, "\ntype Token struct {")
	for _, field := range fields {
		fmt.Fprintf(&buf, "\n%s %s %s // %s", field.name, field.typ, field.jsonTag, field.comment)
	}
	fmt.Fprintf(&buf, "\n}") // end type Token

	fmt.Fprintf(&buf, "\n\nfunc (t *Token) Get(s string) (interface{}, bool) {")
	fmt.Fprintf(&buf, "\nswitch s {")
	for _, field := range fields {
		fmt.Fprintf(&buf, "\ncase %sKey:", field.UpperName())
		switch {
		case field.IsList():
			fmt.Fprintf(&buf, "\nif len(t.%s) == 0 {", field.name)
			fmt.Fprintf(&buf, "\nreturn nil, false")
			fmt.Fprintf(&buf, "\n}") // end if len(t.%s) == 0
			fmt.Fprintf(&buf, "\nreturn ")
			// some types such as `aud` need explicit conversion
			var pre, post string
			if field.typ == "StringList" {
				pre = "[]string("
				post = ")"
			}
			fmt.Fprintf(&buf, "%st.%s%s, true", pre, field.name, post)
		case field.IsPointer():
			fmt.Fprintf(&buf, "\nif t.%s == nil {", field.name)
			fmt.Fprintf(&buf, "\nreturn nil, false")
			fmt.Fprintf(&buf, "\n} else {")
			if field.noDeref {
				if field.typ == "*NumericDate" {
					fmt.Fprintf(&buf, "\nreturn t.%s.Get(), true", field.name)
				} else {
					fmt.Fprintf(&buf, "\nreturn t.%s, true", field.name)
				}
			} else {
				fmt.Fprintf(&buf, "\nreturn *(t.%s), true", field.name)
			}
			fmt.Fprintf(&buf, "\n}") // end if t.%s != nil
		}
	}
	fmt.Fprintf(&buf, "\n}") // end switch
	fmt.Fprintf(&buf, "\nif v, ok := t.PrivateClaims[s]; ok {")
	fmt.Fprintf(&buf, "\nreturn v, true")
	fmt.Fprintf(&buf, "\n}") // end if v, ok := t.privateClaims[s]
	fmt.Fprintf(&buf, "\nreturn nil, false")
	fmt.Fprintf(&buf, "\n}") // end of Get

	fmt.Fprintf(&buf, "\n\nfunc (t *Token) Set(name string, v interface{}) error {")
	fmt.Fprintf(&buf, "\nswitch name {")
	for _, field := range fields {
		fmt.Fprintf(&buf, "\ncase %sKey:", field.UpperName())
		switch {
		case field.hasAccept:
			if field.IsPointer() {
				fmt.Fprintf(&buf, "\nvar x %s", field.PointerElem())
			} else {
				fmt.Fprintf(&buf, "\nvar x %s", field.typ)
			}
			fmt.Fprintf(&buf, "\nif err := x.Accept(v); err != nil {")
			fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `invalid value for '%s' key`)", field.name)
			fmt.Fprintf(&buf, "\n}")
			if field.IsPointer() {
				fmt.Fprintf(&buf, "\nt.%s = &x", field.name)
			} else {
				fmt.Fprintf(&buf, "\nt.%s = x", field.name)
			}
		case field.IsPointer():
			fmt.Fprintf(&buf, "\nx, ok := v.(%s)", field.PointerElem())
			fmt.Fprintf(&buf, "\nif !ok {")
			fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid type for '%s' key: %%T`, v)", field.name)
			fmt.Fprintf(&buf, "\n}") // end if !ok
			fmt.Fprintf(&buf, "\nt.%s = &x", field.name)
		case field.IsList():
			fmt.Fprintf(&buf, "\nswitch x := v.(type) {")
			fmt.Fprintf(&buf, "\ncase %s:", field.ListElem())
			fmt.Fprintf(&buf, "\nt.%s = []string{x}", field.name)
			fmt.Fprintf(&buf, "\ncase %s:", field.typ)
			fmt.Fprintf(&buf, "\nt.%s = x", field.name)
			fmt.Fprintf(&buf, "\ndefault:")
			fmt.Fprintf(&buf, "\nreturn errors.Errorf(`invalid type for '%s' key: %%T`, v)", field.name)
			fmt.Fprintf(&buf, "\n}") // end of switch x := v.(type) {")
		}
	}
	fmt.Fprintf(&buf, "\ndefault:")
	fmt.Fprintf(&buf, "\nif t.PrivateClaims == nil {")
	fmt.Fprintf(&buf, "\nt.PrivateClaims = map[string]interface{}{}")
	fmt.Fprintf(&buf, "\n}") // end if h.PrivateParams == nil
	fmt.Fprintf(&buf, "\nt.PrivateClaims[name] = &v")
	fmt.Fprintf(&buf, "\n}") // end switch name
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}") // end func (h *StandardHeaders) Set(name string, value interface{})

	for _, field := range fields {
		switch {
		case field.IsList():
			fmt.Fprintf(&buf, "\n\nfunc (t Token) %s() %s {", field.method, field.typ)
			fmt.Fprintf(&buf, "\nif v, ok := t.Get(%sKey); ok {", field.UpperName())
			fmt.Fprintf(&buf, "\nreturn v.([]string)")
			fmt.Fprintf(&buf, "\n}") // end if v, ok := t.Get(%sKey)
			fmt.Fprintf(&buf, "\nreturn nil")
			fmt.Fprintf(&buf, "\n}") // end func (t Token) %s() %s
		case field.typ == "*NumericDate":
			fmt.Fprintf(&buf, "\n\nfunc (t Token) %s() time.Time {", field.method)
			fmt.Fprintf(&buf, "\nif v, ok := t.Get(%sKey); ok {", field.UpperName())
			fmt.Fprintf(&buf, "\nreturn v.(time.Time)")
			fmt.Fprintf(&buf, "\n}")
			fmt.Fprintf(&buf, "\nreturn time.Time{}")
			fmt.Fprintf(&buf, "\n}") // end func (t Token) %s()
		case field.IsPointer():
			fmt.Fprintf(&buf, "\n\n// %s is a convenience function to retrieve the corresponding value store in the token", field.UpperName())
			fmt.Fprintf(&buf, "\n// if there is a problem retrieving the value, the zero value is returned. If you need to differentiate between existing/non-existing values, use `Get` instead")
			fmt.Fprintf(&buf, "\n\nfunc (t Token) %s() %s {", field.method, field.PointerElem())
			fmt.Fprintf(&buf, "\nif v, ok := t.Get(%sKey); ok {", field.UpperName())
			fmt.Fprintf(&buf, "\nreturn v.(%s)", field.PointerElem())
			fmt.Fprintf(&buf, "\n}") // end if v, ok := t.Get(%sKey)
			fmt.Fprintf(&buf, "\nreturn %s", zeroval(field.PointerElem()))
			fmt.Fprintf(&buf, "\n}") // end func (t Token) %s() %s
		}
	}

	// JSON related stuff
	fmt.Fprintf(&buf, "\n\n// this is almost identical to json.Encoder.Encode(), but we use Marshal")
	fmt.Fprintf(&buf, "\n// to avoid having to remove the trailing newline for each successive")
	fmt.Fprintf(&buf, "\n// call to Encode()")
	fmt.Fprintf(&buf, "\nfunc writeJSON(buf *bytes.Buffer, v interface{}, keyName string) error {")
	fmt.Fprintf(&buf, "\nif enc, err := json.Marshal(v); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to encode '%%s'`, keyName)")
	fmt.Fprintf(&buf, "\n} else {")
	fmt.Fprintf(&buf, "\nbuf.Write(enc)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\n// MarshalJSON serializes the token in JSON format. This exists to")
	fmt.Fprintf(&buf, "\n// allow flattening of private claims.")
	fmt.Fprintf(&buf, "\nfunc (t Token) MarshalJSON() ([]byte, error) {")
	fmt.Fprintf(&buf, "\nvar buf bytes.Buffer")
	fmt.Fprintf(&buf, "\nbuf.WriteRune('{')")

	for i, field := range fields {
		if strings.HasPrefix(field.typ, "*") {
			fmt.Fprintf(&buf, "\nif t.%s != nil {", field.name)
		} else {
			fmt.Fprintf(&buf, "\nif len(t.%s) > 0 {", field.name)
		}
		if i > 0 {
			fmt.Fprintf(&buf, "\nif buf.Len() > 1 {")
			fmt.Fprintf(&buf, "\nbuf.WriteRune(',')")
			fmt.Fprintf(&buf, "\n}")
		}
		fmt.Fprintf(&buf, "\nbuf.WriteRune('\"')")
		fmt.Fprintf(&buf, "\nbuf.WriteString(%sKey)", field.UpperName())
		fmt.Fprintf(&buf, "\nbuf.WriteString(`\":`)")
		fmt.Fprintf(&buf, "\nif err := writeJSON(&buf, t.%s, %sKey); err != nil {", field.name, field.UpperName())
		fmt.Fprintf(&buf, "\nreturn nil, err")
		fmt.Fprintf(&buf, "\n}")
		fmt.Fprintf(&buf, "\n}")
	}

	fmt.Fprintf(&buf, "\nif len(t.PrivateClaims) == 0 {")
	fmt.Fprintf(&buf, "\nbuf.WriteRune('}')")
	fmt.Fprintf(&buf, "\nreturn buf.Bytes(), nil")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n// If private claims exist, they need to flattened and included in the token")
	fmt.Fprintf(&buf, "\npcjson, err := json.Marshal(t.PrivateClaims)")
	fmt.Fprintf(&buf, "\nif err != nil {")
	fmt.Fprintf(&buf, "\nreturn nil, errors.Wrap(err, `failed to marshal private claims`)")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n// remove '{' from the private claims")
	fmt.Fprintf(&buf, "\npcjson = pcjson[1:]")
	fmt.Fprintf(&buf, "\nif buf.Len() > 1 {")
	fmt.Fprintf(&buf, "\nbuf.WriteRune(',')")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nbuf.Write(pcjson)")
	fmt.Fprintf(&buf, "\nreturn buf.Bytes(), nil")
	fmt.Fprintf(&buf, "\n}")

	fmt.Fprintf(&buf, "\n\n// UnmarshalJSON deserializes data from a JSON data buffer into a Token")
	fmt.Fprintf(&buf, "\nfunc (t *Token) UnmarshalJSON(data []byte) error {")
	fmt.Fprintf(&buf, "\nvar m map[string]interface{}")
	fmt.Fprintf(&buf, "\nif err := json.Unmarshal(data, &m); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrap(err, `failed to unmarshal token`)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nfor name, value := range m {")
	fmt.Fprintf(&buf, "\nif err := t.Set(name, value); err != nil {")
	fmt.Fprintf(&buf, "\nreturn errors.Wrapf(err, `failed to set value for %%s`, name)")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\n}")
	fmt.Fprintf(&buf, "\nreturn nil")
	fmt.Fprintf(&buf, "\n}")

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		log.Printf("%s", buf.Bytes())
		log.Printf("%s", err)
		return errors.Wrap(err, `failed to format source`)
	}

	filename := "token_gen.go"
	f, err := os.Create(filename)
	if err != nil {
		return errors.Wrapf(err, `failed to open file %s for writing`, filename)
	}
	defer f.Close()

	f.Write(formatted)
	return nil
}
