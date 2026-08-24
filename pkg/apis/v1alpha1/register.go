package v1alpha1

// GroupName is the group name used in this package.
const GroupName = "cni.coordino.io"

// GroupVersion contains the group and version for the API.
type GroupVersion struct {
	Group   string
	Version string
}

// GroupResource contains the group and resource name.
type GroupResource struct {
	Group    string
	Resource string
}

// SchemeGroupVersion is group version used to register these objects.
var SchemeGroupVersion = GroupVersion{Group: GroupName, Version: "v1alpha1"}

// SchemeBuilder and AddToScheme are stubs to satisfy the API structure without k8s dependencies.
var (
	SchemeBuilder = struct{}{}
	AddToScheme   = func(interface{}) error { return nil }
)

// Resource takes an unqualified resource and returns a Group qualified GroupResource.
func Resource(resource string) GroupResource {
	return GroupResource{Group: GroupName, Resource: resource}
}
