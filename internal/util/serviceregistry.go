package util

import (
	"go-micro.dev/v4"
	"go-micro.dev/v4/registry"
	"jochum.dev/jo-micro/auth2/shared/sutil"
)

type ServiceListResult map[*registry.Service][]*registry.Endpoint

type WrappedEndpoint struct {
	Pre     string
	Handler string
}

func Endpoints(service micro.Service, regService *registry.Service) ([]*registry.Endpoint, error) {
	if len(regService.Endpoints) > 0 {
		eps := append([]*registry.Endpoint{}, regService.Endpoints...)
		return eps, nil
	}
	// lookup the endpoints otherwise
	newServices, err := service.Options().Registry.GetService(regService.Name)
	if err != nil {
		return []*registry.Endpoint{}, err
	}
	if len(newServices) == 0 {
		return []*registry.Endpoint{}, err
	}

	eps := []*registry.Endpoint{}
	for _, s := range newServices {
		eps = append(eps, s.Endpoints...)
	}

	return eps, nil
}

func ListEndpoints(service micro.Service) (ServiceListResult, error) {
	services, err := service.Options().Registry.ListServices()
	if err != nil {
		return nil, err
	}

	endpoints := make(ServiceListResult)
	for _, srv := range services {
		eps, err := Endpoints(service, srv)
		if err != nil {
			continue
		}

		endpoints[srv] = eps
	}

	return endpoints, nil
}

func FindByEndpoint(service micro.Service, endpoint interface{}) ([]*registry.Service, error) {
	services, err := ListEndpoints(service)
	if err != nil {
		return []*registry.Service{}, err
	}

	strEndpoint := sutil.ReflectFunctionName(endpoint)
	result := []*registry.Service{}
	for s, eps := range services {
		for _, ep := range eps {
			if ep.Name == strEndpoint {
				result = append(result, s)
			}
		}
	}

	return result, nil
}
