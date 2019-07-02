package frontman

import "github.com/pkg/errors"

func newEmptyFieldError(name string) error {
	err := errors.Errorf("unexpected empty field %s", name)
	return errors.Wrap(err, "the field must be filled with details of your Cloudradar account")
}

func newFieldError(name string, err error) error {
	return errors.Wrapf(err, "%s field verification failed", name)
}
