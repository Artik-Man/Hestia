package panel

import "github.com/Artik-Man/Hestia/internal/platformhelper"

// installedHelperTransport is the installed privilege-boundary composition used by panel writers.
var installedHelperTransport platformhelper.Transport = platformhelper.Installed{}
