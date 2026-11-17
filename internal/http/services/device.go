package services

import "strings"

func describeAgent(ua string) (device, browser string) {
	switch {
	case strings.Contains(ua, "iPhone"):
		device = "iPhone"
	case strings.Contains(ua, "iPad"):
		device = "iPad"
	case strings.Contains(ua, "Android"):
		device = "Android"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		device = "Mac"
	case strings.Contains(ua, "Windows"):
		device = "Windows"
	case strings.Contains(ua, "Linux"):
		device = "Linux"
	default:
		device = "Unknown device"
	}
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	case ua == "":
		browser = "Unknown"
	default:
		browser = "Other"
	}
	return device, browser
}
