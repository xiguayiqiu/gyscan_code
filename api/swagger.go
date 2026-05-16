package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type SwaggerDoc struct {
	OpenAPI string                `json:"openapi"`
	Info    SwaggerInfo           `json:"info"`
	Paths   map[string]SwaggerPath `json:"paths"`
	Servers []SwaggerServer       `json:"servers,omitempty"`
	Host    string                `json:"host,omitempty"`
	BasePath string               `json:"basePath,omitempty"`
}

type SwaggerInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type SwaggerServer struct {
	URL string `json:"url"`
}

type SwaggerPath struct {
	Get    *SwaggerOperation `json:"get,omitempty"`
	Post   *SwaggerOperation `json:"post,omitempty"`
	Put    *SwaggerOperation `json:"put,omitempty"`
	Delete *SwaggerOperation `json:"delete,omitempty"`
	Patch  *SwaggerOperation `json:"patch,omitempty"`
}

type SwaggerOperation struct {
	Summary     string              `json:"summary"`
	Description string              `json:"description"`
	Tags        []string            `json:"tags"`
	Parameters  []SwaggerParameter  `json:"parameters,omitempty"`
	RequestBody *SwaggerRequestBody `json:"requestBody,omitempty"`
	Responses   map[string]SwaggerResponse `json:"responses"`
}

type SwaggerParameter struct {
	Name     string      `json:"name"`
	In       string      `json:"in"`
	Required bool        `json:"required"`
	Schema   SwaggerSchema `json:"schema,omitempty"`
}

type SwaggerRequestBody struct {
	Required bool                   `json:"required"`
	Content  map[string]SwaggerMediaType `json:"content"`
}

type SwaggerMediaType struct {
	Schema SwaggerSchema `json:"schema"`
}

type SwaggerResponse struct {
	Description string `json:"description"`
}

type SwaggerSchema struct {
	Type       string                 `json:"type,omitempty"`
	Format     string                 `json:"format,omitempty"`
	Properties map[string]SwaggerSchema `json:"properties,omitempty"`
}

type SwaggerEndpoint struct {
	Path        string
	Method      string
	Summary     string
	Tags        []string
	Parameters  []SwaggerParameter
	RequiredParams []string
	AuthRequired bool
}

func DiscoverSwagger(swaggerURL string) (*SwaggerDoc, []*APIEndpoint, error) {
	resp, err := http.Get(swaggerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("获取Swagger文档失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("读取Swagger文档失败: %w", err)
	}

	var doc SwaggerDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil, fmt.Errorf("解析Swagger文档失败: %w", err)
	}

	basePath := ""
	if doc.BasePath != "" {
		basePath = doc.BasePath
	}
	if doc.Host != "" {
		basePath = doc.Host + basePath
	}
	if len(doc.Servers) > 0 {
		serverURL := doc.Servers[0].URL
		u, _ := url.Parse(serverURL)
		if u != nil {
			if u.Host != "" {
				basePath = u.Host + u.Path
			} else {
				basePath = u.Path
			}
		}
	}

	var endpoints []*APIEndpoint
	for path, sp := range doc.Paths {
		fullPath := strings.TrimSuffix(basePath, "/") + path

		if sp.Get != nil {
			endpoints = append(endpoints, swaggerToEndpoint(fullPath, "GET", sp.Get))
		}
		if sp.Post != nil {
			endpoints = append(endpoints, swaggerToEndpoint(fullPath, "POST", sp.Post))
		}
		if sp.Put != nil {
			endpoints = append(endpoints, swaggerToEndpoint(fullPath, "PUT", sp.Put))
		}
		if sp.Delete != nil {
			endpoints = append(endpoints, swaggerToEndpoint(fullPath, "DELETE", sp.Delete))
		}
		if sp.Patch != nil {
			endpoints = append(endpoints, swaggerToEndpoint(fullPath, "PATCH", sp.Patch))
		}
	}

	return &doc, endpoints, nil
}

func ParseSwaggerJSON(data []byte) (*SwaggerDoc, []*APIEndpoint, error) {
	var doc SwaggerDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("解析Swagger文档失败: %w", err)
	}

	var endpoints []*APIEndpoint
	for path, sp := range doc.Paths {
		if sp.Get != nil {
			endpoints = append(endpoints, swaggerToEndpoint(path, "GET", sp.Get))
		}
		if sp.Post != nil {
			endpoints = append(endpoints, swaggerToEndpoint(path, "POST", sp.Post))
		}
		if sp.Put != nil {
			endpoints = append(endpoints, swaggerToEndpoint(path, "PUT", sp.Put))
		}
		if sp.Delete != nil {
			endpoints = append(endpoints, swaggerToEndpoint(path, "DELETE", sp.Delete))
		}
		if sp.Patch != nil {
			endpoints = append(endpoints, swaggerToEndpoint(path, "PATCH", sp.Patch))
		}
	}

	return &doc, endpoints, nil
}

func swaggerToEndpoint(path, method string, op *SwaggerOperation) *APIEndpoint {
	var params []Parameter
	for _, p := range op.Parameters {
		params = append(params, Parameter{
			Name:     p.Name,
			Type:     p.Schema.Type,
			Required: p.Required,
		})
	}

	ep := &APIEndpoint{
		Path:       path,
		Methods:    []HTTPMethod{HTTPMethod(method)},
		Parameters: params,
	}

	return ep
}

func ExtractSwaggerEndpoints(doc *SwaggerDoc) []*SwaggerEndpoint {
	var result []*SwaggerEndpoint
	for path, sp := range doc.Paths {
		if sp.Get != nil {
			result = append(result, buildSwaggerEndpoint(path, "GET", sp.Get))
		}
		if sp.Post != nil {
			result = append(result, buildSwaggerEndpoint(path, "POST", sp.Post))
		}
		if sp.Put != nil {
			result = append(result, buildSwaggerEndpoint(path, "PUT", sp.Put))
		}
		if sp.Delete != nil {
			result = append(result, buildSwaggerEndpoint(path, "DELETE", sp.Delete))
		}
		if sp.Patch != nil {
			result = append(result, buildSwaggerEndpoint(path, "PATCH", sp.Patch))
		}
	}
	return result
}

func buildSwaggerEndpoint(path, method string, op *SwaggerOperation) *SwaggerEndpoint {
	se := &SwaggerEndpoint{
		Path:    path,
		Method:  method,
		Summary: op.Summary,
		Tags:    op.Tags,
	}

	for _, p := range op.Parameters {
		se.Parameters = append(se.Parameters, p)
		if p.Required {
			se.RequiredParams = append(se.RequiredParams, p.Name)
		}
	}

	authTags := []string{"auth", "authentication", "login", "token", "bearer", "apiKey", "jwt"}
	for _, tag := range op.Tags {
		for _, at := range authTags {
			if strings.EqualFold(tag, at) {
				se.AuthRequired = true
				break
			}
		}
	}

	return se
}

func SwaggerEndpointsByAuth(endpoints []*SwaggerEndpoint) (auth, noauth []*SwaggerEndpoint) {
	for _, ep := range endpoints {
		if ep.AuthRequired {
			auth = append(auth, ep)
		} else {
			noauth = append(noauth, ep)
		}
	}
	return
}

func SwaggerEndpointsByTag(endpoints []*SwaggerEndpoint) map[string][]*SwaggerEndpoint {
	byTag := make(map[string][]*SwaggerEndpoint)
	for _, ep := range endpoints {
		for _, tag := range ep.Tags {
			byTag[tag] = append(byTag[tag], ep)
		}
	}
	return byTag
}

func SwaggerTestAuthAPIs(endpoints []*SwaggerEndpoint) []*SwaggerEndpoint {
	var result []*SwaggerEndpoint
	for _, ep := range endpoints {
		if !ep.AuthRequired {
			for _, param := range ep.Parameters {
				if param.Name == "Authorization" || param.Name == "authorization" {
					ep.AuthRequired = true
					result = append(result, ep)
					break
				}
			}
		}
	}
	return result
}

func SwaggerCheckUnprotectedSensitiveAPIs(endpoints []*SwaggerEndpoint) []*SwaggerEndpoint {
	var result []*SwaggerEndpoint
	for _, ep := range endpoints {
		if ep.AuthRequired {
			continue
		}
		sensitiveOperations := []string{"create", "update", "delete", "remove", "upload", "admin", "manage"}
		for _, so := range sensitiveOperations {
			if strings.Contains(strings.ToLower(ep.Summary), so) || strings.Contains(strings.ToLower(ep.Path), so) {
				result = append(result, ep)
				break
			}
		}
	}
	return result
}

func SwaggerSummary(endpoints []*SwaggerEndpoint) string {
	if len(endpoints) == 0 {
		return "无Swagger端点"
	}

	byTag := SwaggerEndpointsByTag(endpoints)
	auth, noauth := SwaggerEndpointsByAuth(endpoints)

	result := "Swagger分析摘要:\n"
	result += "  总端点: " + itoa(len(endpoints)) + " 个\n"
	result += "  需要认证: " + itoa(len(auth)) + " 个\n"
	result += "  无需认证: " + itoa(len(noauth)) + " 个\n"
	result += "  标签分组: " + itoa(len(byTag)) + " 个"

	return result
}