// Package strictjson rejects ambiguous JSON before decoding typed contracts.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Decode accepts one bounded JSON value, exact struct-key spelling and no duplicates.
// Dynamic map keys are data. The caller must check required fields and semantic bounds.
func Decode(data []byte, maxBytes int, dst any) error {
	if len(data) == 0 || len(data) > maxBytes || !utf8.Valid(data) {
		return errors.New("JSON byte limit")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := walk(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	t := reflect.TypeOf(dst)
	if t == nil || t.Kind() != reflect.Pointer {
		return errors.New("decoder destination")
	}
	if err := keys(data, t.Elem()); err != nil {
		return err
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(dst)
}
func walk(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON depth limit")
	}
	t, err := d.Token()
	if err != nil {
		return errors.New("invalid JSON")
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return errors.New("invalid object")
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return errors.New("duplicate or invalid key")
			}
			seen[s] = true
			if err := walk(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := walk(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected delimiter")
	}
	end, err := d.Token()
	if err != nil {
		return errors.New("unterminated JSON")
	}
	if (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return errors.New("invalid closing delimiter")
	}
	return nil
}
func keys(data []byte, t reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if json.Unmarshal(data, &obj) != nil || obj == nil {
			return errors.New("expected object")
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			n := strings.Split(f.Tag.Get("json"), ",")[0]
			if n == "" {
				n = f.Name
			}
			if n != "-" && f.IsExported() {
				fields[n] = f.Type
			}
		}
		for k, v := range obj {
			ft, ok := fields[k]
			if !ok {
				return errors.New("unknown or mis-cased field")
			}
			if err := keys(v, ft); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if json.Unmarshal(data, &values) != nil {
			return errors.New("expected array")
		}
		for _, v := range values {
			if err := keys(v, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		var values map[string]json.RawMessage
		if json.Unmarshal(data, &values) != nil {
			return errors.New("expected map")
		}
		for _, v := range values {
			if err := keys(v, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

// Required rejects omitted or null controls before typed zero values could hide them.
func Required(data []byte, names ...string) error {
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) != nil || obj == nil {
		return errors.New("expected object")
	}
	for _, n := range names {
		v, ok := obj[n]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return errors.New("missing or null field")
		}
	}
	return nil
}
