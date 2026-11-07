package keeneticrci

import (
	"context"
	"encoding/json"
)

// RouterVersion contains the stable identity fields returned by show/version.
type RouterVersion struct {
	Model        string `json:"model"`
	Title        string `json:"title"`
	Release      string `json:"release"`
	Architecture string `json:"arch"`
}

// ReadVersion reads and validates the router identity through the shared authenticated client.
func (c *Client) ReadVersion(ctx context.Context) (RouterVersion, error) {
	response, err := c.Do(ctx, Operation{
		Name:   "show_version",
		Path:   "/rci/show/version",
		Method: MethodGet,
	}, nil)
	if err != nil {
		return RouterVersion{}, err
	}
	var version RouterVersion
	if err := json.Unmarshal(response.Body, &version); err != nil || version.Model == "" || version.Title == "" || version.Release == "" || version.Architecture == "" {
		return RouterVersion{}, &Error{Kind: ErrorSchema}
	}
	return version, nil
}
