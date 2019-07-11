package frontman

import "testing"

func TestNeighbor(t *testing.T) {
	// XXX 1. spawn one "neighbor" on another port for the test
	// XXX 2. tell main instance to ping invalid host, see servicecheck_single_broken.json
	// XXX 3. assert neighbor is asked, and that all failed

	// XXX 4. can we somehow block main instance from succeeding while test neighbor could succeed, in order to test fallover?
}
