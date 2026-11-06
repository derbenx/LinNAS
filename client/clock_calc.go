package main

// ComputeClockOffset returns the offset to adjust client timestamps to match server timeline:
// normalizedClientTimestamp = clientTimestamp + clockOffset
func ComputeClockOffset(serverTime, clientTime int64) int64 {
	if serverTime <= 0 || clientTime <= 0 {
		return 0
	}
	diff := serverTime - clientTime
	if diff > 2 || diff < -2 {
		return diff
	}
	return 0
}

// NormalizeClientModTime converts a local client file modTime to the server clock timeline
func NormalizeClientModTime(clientModTime, clockOffset int64) int64 {
	if clientModTime <= 0 {
		return clientModTime
	}
	return clientModTime + clockOffset
}

// LocalComparableServerModTime converts a server file modTime to the client local clock timeline
func LocalComparableServerModTime(serverModTime, clockOffset int64) int64 {
	if serverModTime <= 0 {
		return serverModTime
	}
	return serverModTime - clockOffset
}
