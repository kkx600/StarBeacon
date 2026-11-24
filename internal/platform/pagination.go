package platform

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/httpapi"
)

var errListLimit = errors.New("每页条数应为 10、20、50 或 100")

func parseListLimit(values []string) (int, error) {
	if len(values) == 0 {
		return contract.DefaultListLimit, nil
	}
	if len(values) != 1 {
		return 0, errListLimit
	}
	limit, err := strconv.Atoi(values[0])
	if err != nil || !contract.ValidListLimit(limit) || strconv.Itoa(limit) != values[0] {
		return 0, errListLimit
	}
	return limit, nil
}

func requestListLimit(w http.ResponseWriter, r *http.Request) (int, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err == nil {
		limit, limitErr := parseListLimit(query["limit"])
		if limitErr == nil {
			return limit, true
		}
	}
	httpapi.Fail(w, r, http.StatusBadRequest, "invalid_list_limit", errListLimit.Error())
	return 0, false
}
