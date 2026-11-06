package storage

// Installed selects the layout for this build in one composition point.
// The current standalone build uses Linux; platform builds can replace this selection.
func Installed() Layout { return Linux() }
