package inmem_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/store/contract"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func TestSSFContract(t *testing.T) {
	t.Parallel()

	contract.RunSSF(t, func(*testing.T) contract.SSFBackend {
		s := inmem.New()
		return contract.SSFBackend{Streams: s.SSFStreams(), Events: s.SSFEvents()}
	})
}
