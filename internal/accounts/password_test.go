package accounts

import (
	"strings"
	"testing"
)

func TestPasswordChangeBytesAndRevisionBoundaries(t *testing.T) {
	valid := PasswordChange{ExpectedRevision: 1, CurrentPassword: "old-pass", NewPassword: "password-owned-new-123"}
	if valid.Validate() != nil {
		t.Fatal("合法密码操作被拒绝")
	}
	for _, c := range []PasswordChange{
		{0, valid.CurrentPassword, valid.NewPassword}, {MaxRevision, valid.CurrentPassword, valid.NewPassword},
		{1, "", valid.NewPassword}, {1, strings.Repeat("中", 25), valid.NewPassword}, {1, "old\npassword", valid.NewPassword}, {1, string([]byte{0xff}), valid.NewPassword},
		{1, valid.CurrentPassword, "short"}, {1, valid.CurrentPassword, strings.Repeat("中", 25)}, {1, valid.CurrentPassword, "new\npassword-owned"}, {1, valid.CurrentPassword, string([]byte{0xff}) + strings.Repeat("x", 12)},
		{1, valid.NewPassword, valid.NewPassword},
	} {
		if c.Validate() != ErrInput {
			t.Fatal("非法密码或修订被接受")
		}
	}
	valid.ExpectedRevision = MaxRevision - 1
	valid.NewPassword = strings.Repeat("中", 24)
	if valid.Validate() != nil || !ValidPassword(strings.Repeat("a", 12)) {
		t.Fatal("合法密码字节边界被拒绝")
	}
}
