package stats

// FrontmanStats holds application stats
type FrontmanStats struct {
	BytesSentToHubTotal      uint64
	BytesFetchedFromHubTotal uint64

	ChecksPerformedTotal  uint64
	ChecksFetchedFromHub  uint64
	CheckResultsSentToHub uint64

	HubErrorsTotal        uint64
	HubLastErrorMessage   string
	HubLastErrorTimestamp uint64

	InternalErrorsTotal        uint64
	InternalLastErrorMessage   string
	InternalLastErrorTimestamp uint64

	Uptime uint64
}
