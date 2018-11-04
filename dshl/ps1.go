package dshl

// The default value for Shell.PS1.
var DefaultPS1 = NewPS1("~> ", "!> ")

// A function to be called to get the left-hand prompt (PS1).
type PS1 func(err error) string

// Returns a PS1 that shows a fixed message for successful and unsuccessful last commands.
func NewPS1(succ, unsucc string) PS1 {
	return func(lasterr error) string {
		if lasterr != nil {
			return unsucc
		}
		return succ
	}
}
