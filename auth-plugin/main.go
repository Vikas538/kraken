package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	awsSecrets "krakend-client-example/aws"
	"net/http"
	"time"

	// "krakend-client-example/aws"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

// ClientRegisterer is the symbol the plugin loader will try to load. It must implement the RegisterClient interface
var ClientRegisterer = registerer("auth-plugin")

type registerer string

var logger Logger = nil

var serverSecretKey = ""

var jwtSecretKey = ""

type AuthValidator struct{}

type customClaims struct {
	Message string `json:"message"`
	jwt.StandardClaims
}

type User struct {
	Id     string `json:"id"`
	Server string `json:"server"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type JSONError struct {
	Message    string `json:"message"`
	StatusCode int    `json:"statusCode"`
}

func (e *JSONError) Error() string {
	errJSON, _ := json.Marshal(e)
	return string(errJSON)
}

type Role struct {
	Roles map[string]map[string]struct {
		IsBuyer  []interface{} `json:"isBuyer"`
		IsSeller []interface{} `json:"isSeller"`
	} `json:"roles"`
}

type RoleCache struct{
	ValidTill time.Time 
	Roles    Role  
}

var roleCache RoleCache

// NewAuthValidator initializes a new instance of AuthValidator.

// Validate performs the authentication check.

func (registerer) RegisterLogger(v interface{}) {
	l, ok := v.(Logger)
	if !ok {
		return
	}
	logger = l
	logger.Debug(fmt.Sprintf("[PLUGIN: %s] Logger loaded", ClientRegisterer))
}

func (r registerer) RegisterClients(f func(
	name string,
	handler func(context.Context, map[string]interface{}) (http.Handler, error),
)) {
	f(string(r), r.registerClients)
}

func copyHeaders(dest http.Header, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dest.Add(key, value)
		}
	}
}

func compressJSON(data map[string]interface{}) (string, error) {
	// Marshal the JSON data
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	// Compress the JSON data using Gzip
	var compressedData bytes.Buffer
	writer := gzip.NewWriter(&compressedData)
	_, err = writer.Write(jsonData)
	if err != nil {
		return "", err
	}
	err = writer.Close()
	if err != nil {
		return "", err
	}

	// Base64 encode the compressed data
	base64Encoded := base64.StdEncoding.EncodeToString(compressedData.Bytes())

	return base64Encoded, nil
}

func (r registerer) registerClients(_ context.Context, extra map[string]interface{}) (http.Handler, error) {
	// config, _ := extra[string(r)].(map[string]interface{})
	// path, _ := config["path"].(string)

	// Initialize your authentication logic here
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Perform authentication check
		config, _ := extra["auth-plugin"].(map[string]interface{})
		var url = config["host"].(string)
		var serverSecretName = config["serverSecretName"].(string)
		var jwtSecretName = config["jwtSecretName"].(string)
		var permissions = config["permissions"].(string)
		var isGetToken bool
		if val, ok := config["isGetToken"].(bool); ok {
			isGetToken = val
		} else {
			// Handle the case when the value is not a string or the key is not present
			isGetToken = false
		}
		
		permissionSlice := strings.Split(permissions, ",")
		if serverSecretKey == "" {
			serverKey, errSecrects := awsSecrets.GetSecrets(serverSecretName)
			if errSecrects != nil {
				http.Error(w, "Error fetching secrets", http.StatusInternalServerError)
				return
			}
			serverSecretKey = serverKey["serverSecrectKey"].(string)
		}

		if jwtSecretKey == "" {
			serverKey, errSecrects := awsSecrets.GetSecrets(jwtSecretName)
			if errSecrects != nil {
				http.Error(w, "Error fetching secrets", http.StatusInternalServerError)
				return
			}
			jwtSecretKey = serverKey["secret"].(string)
		}

		header := req.Header.Get("Authorization")
		authTokenString := strings.Split(header, " ")[1]

		payload, err := parseToken(authTokenString, []byte(jwtSecretKey))
		if err != nil {
			http.Error(w, "Unauthorzed Bye Bye", http.StatusUnauthorized)
			return
		}
		userType := getUserType(payload)

		workspaceRoles := payload["workspaceRoles"].([]interface{})

		
		if len(permissions) > 0 {
		rolesAndPermission, e := getRoles(url+"/all/workspaces/roles/permissions", []byte(serverSecretKey))
		if e != nil {
			panic(e)
		}
			userPermitted, errorCheckingPermissions := checkUserPermissions(workspaceRoles, permissionSlice, userType, *rolesAndPermission)
			if errorCheckingPermissions != nil {
				http.Error(w, "Failed to check user permissions", http.StatusInternalServerError)
				return
			}
			if !userPermitted {
				http.Error(w, "You are not authorized to perform this action", http.StatusForbidden)
				return
			}
		}

		userData, err := getUserDetails(url, req)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			apiError, ok := err.(*JSONError)
			if !ok {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(apiError.StatusCode)
			responseBody, _ := json.Marshal(apiError)
			w.Write(responseBody)
			return
		}
		compressedJson, _ := compressJSON(userData)
		if err != nil {
			http.Error(w, "Error marshaling response to JSON", http.StatusInternalServerError)
			return
		}

		// Create custom claims
		claims := customClaims{
			Message: string(compressedJson),
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 1).Unix(), // Token expiration time
				Issuer:    "my-issuer",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		// Sign the token with the secret key
		serverTokenStringWithUserData, err := token.SignedString([]byte(serverSecretKey))
		if err != nil {
			http.Error(w, "Error creating JWT token ="+serverSecretName, http.StatusInternalServerError)
			return
		}
		if isGetToken {
			w.Write([]byte(serverTokenStringWithUserData))
		}
		req.Header.Set("Authorization", "Bearer "+serverTokenStringWithUserData)
		// Set the content type to JSON
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Copy headers, status codes, and body from the backend to the response writer
		for k, hs := range resp.Header {
			for _, h := range hs {
				w.Header().Add(k, h)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if resp.Body == nil {
			return
		}
		io.Copy(w, resp.Body)
		resp.Body.Close()
	}), nil
}

func main() {
}

type Logger interface {
	Debug(v ...interface{})
	Info(v ...interface{})
	Warning(v ...interface{})
	Error(v ...interface{})
	Critical(v ...interface{})
	Fatal(v ...interface{})
}

func getSellerWorkSpaceIdFromPath(r *http.Request) string {
	vars := mux.Vars(r)
	id, ok := vars["id"]
	if !ok {
		fmt.Println("path param is not passed")
		return ""
	}
	return id
}

func getSellerWorkSpaceIdFromQuery(r *http.Request) string {
	sellerWorkSpaceId := r.URL.Query().Get("sellerWorkspaceId")
	return sellerWorkSpaceId
}

func getSellerWorkSpaceIdFromBody(r *http.Request) string {
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		return ""
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	var requestBody map[string]interface{}
	if err := json.Unmarshal(body, &requestBody); err != nil {
		return ""
	}
	sellerWorkspaceId, _ := requestBody["sellerWorkspaceId"].(string)
	return sellerWorkspaceId
}

func getSellerWorkSpaceId(r *http.Request) string {
	workspaceId := getSellerWorkSpaceIdFromQuery(r)
	if workspaceId == "" {
		workspaceId = getSellerWorkSpaceIdFromBody(r)
	}
	if workspaceId == "" {
		workspaceId = getSellerWorkSpaceIdFromPath(r)
	}
	return workspaceId
}

func getUserDetails(baseUrl string, r *http.Request) (map[string]interface{}, error) {

	sellerWorkSpaceId := getSellerWorkSpaceId(r)
	if sellerWorkSpaceId == "" {
		return nil, &JSONError{Message: "Invalid workspaceId", StatusCode: http.StatusBadRequest}
	}
	baseUrl = baseUrl + "" + "/users/me/v2?includeCFA=true&sellerWorkspaceId=" + sellerWorkSpaceId
	targetReq, err := http.NewRequest(http.MethodGet, baseUrl, nil)
	if err != nil {
		return nil, &JSONError{Message: "Something went worg", StatusCode: http.StatusInternalServerError}
	}
	copyHeaders(targetReq.Header, r.Header)
	client := http.DefaultClient
	response, err := client.Do(targetReq)
	if err != nil {
		return nil, &JSONError{Message: "Error fetching user data", StatusCode: http.StatusInternalServerError}
	}
	var userData map[string]interface{}
	responseBody, _ := io.ReadAll(response.Body)
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		var userData map[string]interface{}
		if err := json.Unmarshal(responseBody, &userData); err != nil {
			return nil, &JSONError{Message: "Something went wrong", StatusCode: http.StatusInternalServerError}
		}

		message, ok := userData["message"].(string)
		if !ok {
			return nil, &JSONError{Message: "Invalid response format", StatusCode: http.StatusInternalServerError}
		}
		return nil, &JSONError{Message: message, StatusCode: http.StatusUnauthorized}
	}
	if response.StatusCode == http.StatusInternalServerError {
		return nil, &JSONError{Message: "something went wrong", StatusCode: http.StatusUnauthorized}
	}

	e := json.Unmarshal(responseBody, &userData)
	if e != nil {
		return nil, fmt.Errorf("invalid Used Data")
	}
	return userData, nil
}

func parseToken(tokenString string, mySigningKey []byte) (map[string]interface{}, error) {
	// Parse the token using the key func and the token string.
	var user map[string]interface{}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Return the secret key for validation
		return mySigningKey, nil
	})
	if err != nil {
		return nil, &JSONError{Message: "Unauthorzed token", StatusCode: http.StatusUnauthorized}
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// Assuming your payload structure has a "user" field
		user = claims["user"].(map[string]interface{})
		// Send the user object in the response
	} else {
		return nil, &JSONError{Message: "Token expired", StatusCode: http.StatusUnauthorized}
	}

	return user, nil
}

func getRoles(baseUrl string, mySigningKey []byte) (*Role, error) {

	if time.Now().Before(roleCache.ValidTill) {
		fmt.Println("=====================================> Roles are still valid. Roles:")
		return &roleCache.Roles,nil
	}
	token, _ := createServerToken(mySigningKey)
	targetReq, err := http.NewRequest(http.MethodGet, baseUrl, nil)
	if err != nil {
		return nil, &JSONError{Message: "Something went wrong", StatusCode: http.StatusInternalServerError}
	}
	targetReq.Header.Set("Authorization", "Bearer "+token)

	client := http.DefaultClient
	response, err := client.Do(targetReq)
	if err != nil {
		return nil, &JSONError{Message: "Error fetching user data", StatusCode: http.StatusInternalServerError}
	}

	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, &JSONError{Message: "Error reading response body", StatusCode: http.StatusInternalServerError}
	}

	if response.StatusCode == http.StatusUnauthorized {
		var authError struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(responseBody, &authError); err != nil {
			return nil, &JSONError{Message: "Invalid response format", StatusCode: http.StatusInternalServerError}
		}
		return nil, &JSONError{Message: authError.Message, StatusCode: http.StatusUnauthorized}
	}

	if response.StatusCode == http.StatusInternalServerError {
		return nil, &JSONError{Message: "Something went wrong", StatusCode: http.StatusInternalServerError}
	}

	var userData Role
	if err := json.Unmarshal(responseBody, &userData); err != nil {
		return nil, &JSONError{Message: "Invalid response format", StatusCode: http.StatusInternalServerError}
	}

	roleCache = RoleCache{
		ValidTill: time.Now().Add(1 * time.Minute),
		Roles: userData,
	}

	return &userData, nil
}

func checkUserPermissions(workspaceRoles []interface{}, permissions []string, userType string, rolesAndPermissions Role) (bool, error) {

	if len(workspaceRoles) == 0 {
		return false, &JSONError{Message: "User doesn't have enough permission to perform this action"}
	}

	var memberPermissions []interface{}
	for _, role := range workspaceRoles {
		roleStr, _ := role.(string)
		memberPermissions = append(memberPermissions, rolesAndPermissions.Roles[userType][roleStr].IsBuyer...)
	}

	var hasPermission bool

	for _, permission := range permissions {
		hasPermission = includes(memberPermissions, permission)
		if !hasPermission {
			break
		}
	}
	return hasPermission, nil
}

func includes(slice []interface{}, element string) bool {
	for _, value := range slice {
		if value == element {
			return true
		}
	}
	return false
}

func getUserType(user map[string]interface{}) string {
	userType, ok := user["userType"].(string)
	if !ok || userType == "" || userType == "C" {
		userType = "isBuyer"
	} else {
		userType = "isSeller"
	}
	return userType
}

func createServerToken(mySigningKey []byte) (string, error) {
	// Create a new token with a signing method and claims.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": User{
			Id: "07d0e3a7-2a03-4492-a902-bce9e88b0256",
		},
		"server": "zonoadmin",
		"exp":    time.Now().Add(time.Hour * 1).Unix(),
	})

	// Sign and get the complete encoded token as a string.
	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
