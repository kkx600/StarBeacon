package contract

const DefaultListLimit = 20

func ValidListLimit(limit int) bool {
	switch limit {
	case 10, 20, 50, 100:
		return true
	default:
		return false
	}
}
