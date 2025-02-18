package schema

import "github.com/abhishek262/scim/optional"

// ComplexParams are the parameters used to create a complex attribute.
type ComplexParams struct {
	Description   optional.String
	MultiValued   bool
	Mutability    AttributeMutability
	Name          string
	Required      bool
	Returned      AttributeReturned
	SubAttributes []SimpleParams
	Uniqueness    AttributeUniqueness
}
