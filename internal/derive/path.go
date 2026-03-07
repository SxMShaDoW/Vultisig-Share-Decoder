package derive

import (
	"fmt"
	"strconv"
	"strings"
)

func getDerivePathBytes(derivePath string) ([]uint32, error) {
	var pathBuf []uint32
	for _, item := range strings.Split(derivePath, "/") {
		if len(item) == 0 || item == "m" {
			continue
		}
		result := strings.Trim(item, "'")
		intResult, err := strconv.Atoi(result)
		if err != nil {
			return nil, fmt.Errorf("invalid path: %w", err)
		}
		if intResult < 0 || intResult > int(^uint32(0)) {
			return nil, fmt.Errorf("integer value %d cannot fit into a uint32", intResult)
		}
		pathBuf = append(pathBuf, uint32(intResult))
	}
	return pathBuf, nil
}
