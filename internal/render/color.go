package render

import "fmt"

// ColorEnabled controls whether ANSI color codes are emitted.
var ColorEnabled = true

// ANSI escape codes.
const (
	reset     = "\033[0m"
	bold      = "\033[1m"
	dim       = "\033[2m"
	italic    = "\033[3m"
	underline = "\033[4m"

	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	white   = "\033[37m"

	bgRed    = "\033[41m"
	bgYellow = "\033[43m"
	bgBlue   = "\033[44m"

	brightRed    = "\033[91m"
	brightGreen  = "\033[92m"
	brightYellow = "\033[93m"
	brightCyan   = "\033[96m"
	brightWhite  = "\033[97m"
)

func c(style, text string) string {
	if !ColorEnabled {
		return text
	}
	return style + text + reset
}

func cb(style, text string) string {
	if !ColorEnabled {
		return text
	}
	return bold + style + text + reset
}

func severityColor(sev string) string {
	switch sev {
	case "HIGH":
		return brightRed
	case "MEDIUM":
		return brightYellow
	case "LOW":
		return blue
	default:
		return white
	}
}

func severityBadge(sev string) string {
	if !ColorEnabled {
		return fmt.Sprintf("[%s]", sev)
	}
	switch sev {
	case "HIGH":
		return bold + bgRed + brightWhite + " HIGH " + reset
	case "MEDIUM":
		return bold + bgYellow + "\033[30m" + " MED  " + reset
	case "LOW":
		return bold + bgBlue + brightWhite + " LOW  " + reset
	default:
		return fmt.Sprintf("[%s]", sev)
	}
}

func tagColor(tag string) string {
	switch tag {
	case "security":
		return red
	case "downtime":
		return brightRed
	case "network":
		return magenta
	case "ops":
		return yellow
	case "capacity":
		return yellow
	case "data":
		return brightRed
	case "cost":
		return cyan
	default:
		return white
	}
}
