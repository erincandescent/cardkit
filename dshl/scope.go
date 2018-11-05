package dshl

// A Scope represents a scope in the shell, holding variables and commands.
// Scopes can be stacked, in a reverse linked list structure, and shadow each other.
type Scope struct {
	Parent *Scope // Parent scope.
	Modal  bool   // A modal scope can be exitted with Ctrl+D.
	PS1    PS1    // PS1 associated with this scope; can be shadowed.

	vars map[string]interface{}
}

// Returns a child scope, with this scope set as its parent.
func (s *Scope) Child() *Scope {
	return &Scope{Parent: s}
}

// Set the given name to a value. Shadows lower scopes.
func (s *Scope) Set(name string, v interface{}) {
	if s.vars == nil {
		s.vars = map[string]interface{}{name: v}
	} else {
		s.vars[name] = v
	}
}

// Sets a name to a value, attempting first to overwrite an existing instance of it, then resorting
// to creating it in the current scope.
func (s *Scope) Assign(name string, v interface{}) {
	_, vs := s.lookup(name)
	if vs == nil {
		vs = s
	}
	vs.Set(name, v)
}

// Looks up the given name in this state or any higher ones.
// Returns an untyped (interface{}) nil if nothing is found.
func (s *Scope) Get(name string) interface{} {
	v, _ := s.lookup(name)
	return v
}

// Deletes the given name. It can be in this scope or in a lower one.
func (s *Scope) Delete(name string) {
	_, vs := s.lookup(name)
	if vs != nil {
		delete(vs.vars, name)
	}
}

// Returns a map of all members visible in this scope and any parent scopes.
func (s *Scope) All() map[string]interface{} {
	out := make(map[string]interface{})
	scope := s
	for scope != nil {
		for k, v := range scope.vars {
			if _, ok := out[k]; !ok {
				out[k] = v
			}
		}
		scope = scope.Parent
	}
	return out
}

// Look up a name and the scope it's in.
func (s *Scope) lookup(name string) (interface{}, *Scope) {
	v, ok := s.vars[name]
	if !ok && s.Parent != nil {
		return s.Parent.lookup(name)
	}
	return v, s
}
