package functions

// Region selects the region an Edge Function is invoked in. The zero value
// and RegionAny let the platform route the request.
type Region string

// Regions supported by Supabase Edge Functions (upstream FunctionRegion).
const (
	RegionAny          Region = "any"
	RegionApNortheast1 Region = "ap-northeast-1"
	RegionApNortheast2 Region = "ap-northeast-2"
	RegionApSouth1     Region = "ap-south-1"
	RegionApSoutheast1 Region = "ap-southeast-1"
	RegionApSoutheast2 Region = "ap-southeast-2"
	RegionCaCentral1   Region = "ca-central-1"
	RegionEuCentral1   Region = "eu-central-1"
	RegionEuWest1      Region = "eu-west-1"
	RegionEuWest2      Region = "eu-west-2"
	RegionEuWest3      Region = "eu-west-3"
	RegionSaEast1      Region = "sa-east-1"
	RegionUsEast1      Region = "us-east-1"
	RegionUsWest1      Region = "us-west-1"
	RegionUsWest2      Region = "us-west-2"
)

// String returns the region identifier sent on the wire.
func (r Region) String() string { return string(r) }
