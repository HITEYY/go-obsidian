// Copyright 2026 The go-obsidian Authors

package legacypool

import (
	"testing"

	"github.com/HITEYY/go-obsidian/core/types"
)

func TestFilterAcceptsAAUserOpTx(t *testing.T) {
	pool := &LegacyPool{}
	tx := types.NewTx(&types.AAUserOpTx{})
	if !pool.Filter(tx) {
		t.Fatal("legacy pool should accept AA user operation transactions")
	}
}
