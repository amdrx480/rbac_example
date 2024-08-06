package main

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

// JwtCustomClaims holds custom claims for JWT
type JwtCustomClaims struct {
	ID   int    `json:"id"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// JWTConfig holds the configuration for JWT
type JWTConfig struct {
	SecretKey       string
	ExpiresDuration int
}

// Init initializes JWT configuration
func (jwtConfig *JWTConfig) Init() echojwt.Config {
	return echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(JwtCustomClaims)
		},
		SigningKey: []byte(jwtConfig.SecretKey),
	}
}

// GenerateToken generates a JWT token
func (jwtConfig *JWTConfig) GenerateToken(userID int, userRole string) (string, error) {
	expire := jwt.NewNumericDate(time.Now().Local().Add(time.Hour * time.Duration(jwtConfig.ExpiresDuration)))

	claims := &JwtCustomClaims{
		ID:   userID,
		Role: userRole,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: expire,
		},
	}

	rawToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := rawToken.SignedString([]byte(jwtConfig.SecretKey))
	if err != nil {
		return "", err
	}
	return token, nil
}

// GetUser extracts user data from context
func GetUser(c echo.Context) (*JwtCustomClaims, error) {
	user := c.Get("user").(*jwt.Token)
	if user == nil {
		return nil, errors.New("invalid token")
	}

	claims, ok := user.Claims.(*JwtCustomClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

// VerifyRole middleware to check if the user has the required role
func VerifyRole(requiredRole string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userData, err := GetUser(c)
			if userData == nil || err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"message": "invalid token",
				})
			}

			if userData.Role != requiredRole {
				return c.JSON(http.StatusForbidden, map[string]string{
					"message": "access forbidden",
				})
			}

			return next(c)
		}
	}
}

// HashPassword hashes the password
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// SeedDatabase seeds the database with admin and user data
func SeedDatabase(db *sql.DB) {
	adminPasswordHash, err := hashPassword("admin123")
	if err != nil {
		log.Fatalf("Failed to hash admin password: %v", err)
	}

	userPasswordHash, err := hashPassword("user123")
	if err != nil {
		log.Fatalf("Failed to hash user password: %v", err)
	}

	// Create table if not exists
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL
    )`)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	// Insert admin and user
	_, err = db.Exec(`INSERT IGNORE INTO users (username, password, role) VALUES
        ('admin', ?, 'admin'),
        ('user', ?, 'user')`, adminPasswordHash, userPasswordHash)
	if err != nil {
		log.Fatalf("Failed to insert seed data: %v", err)
	}
}

// LoginRequest represents the JSON structure for login requests
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// RegisterRequest represents the JSON structure for register requests
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func main() {
	e := echo.New()

	// Connect to MySQL database
	dsn := "root:root123@tcp(127.0.0.1:3306)/rbac_example"
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Seed the database with admin and user data
	SeedDatabase(db)

	// JWT configuration
	jwtConfig := &JWTConfig{
		SecretKey:       "your_secret_key",
		ExpiresDuration: 72, // Token expiration in hours
	}

	// Public endpoint to register a new user
	e.POST("/register", func(c echo.Context) error {
		var registerReq RegisterRequest
		if err := c.Bind(&registerReq); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
		}

		username := registerReq.Username
		password := registerReq.Password
		role := registerReq.Role

		// Hash the password
		passwordHash, err := hashPassword(password)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to hash password"})
		}

		// Insert the new user into the database
		_, err = db.Exec(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, username, passwordHash, role)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to register user"})
		}

		return c.JSON(http.StatusOK, map[string]string{"message": "User registered successfully"})
	})

	// Public endpoint to login and generate token
	e.POST("/login", func(c echo.Context) error {
		var loginReq LoginRequest
		if err := c.Bind(&loginReq); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
		}

		username := loginReq.Username
		password := loginReq.Password

		// Perform user authentication here (e.g., check username and password from database)
		var storedPasswordHash string
		var role string
		err := db.QueryRow("SELECT password, role FROM users WHERE username = ?", username).Scan(&storedPasswordHash, &role)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid credentials"})
		}

		// Verify password
		if err := bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(password)); err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid credentials"})
		}

		// Generate token
		userID := 1 // This should be fetched from the database
		token, err := jwtConfig.GenerateToken(userID, role)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Could not generate token"})
		}

		return c.JSON(http.StatusOK, map[string]string{"token": token})
	})

	// Group with JWT middleware
	r := e.Group("/restricted")
	r.Use(echojwt.WithConfig(jwtConfig.Init()))

	// Admin endpoint
	r.GET("/admin", VerifyRole("admin")(func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "Welcome, admin!"})
	}))

	// User endpoint
	r.GET("/user", VerifyRole("user")(func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "Welcome, user!"})
	}))

	// Start the server
	e.Logger.Fatal(e.Start(":8080"))
}

// package main

// import (
// 	"database/sql"
// 	"errors"
// 	"log"
// 	"net/http"
// 	"time"

// 	_ "github.com/go-sql-driver/mysql"
// 	"github.com/golang-jwt/jwt/v5"
// 	echojwt "github.com/labstack/echo-jwt/v4"
// 	"github.com/labstack/echo/v4"
// 	"golang.org/x/crypto/bcrypt"
// )

// // JwtCustomClaims holds custom claims for JWT
// type JwtCustomClaims struct {
// 	ID   int    `json:"id"`
// 	Role string `json:"role"`
// 	jwt.RegisteredClaims
// }

// // JWTConfig holds the configuration for JWT
// type JWTConfig struct {
// 	SecretKey       string
// 	ExpiresDuration int
// }

// // Init initializes JWT configuration
// func (jwtConfig *JWTConfig) Init() echojwt.Config {
// 	return echojwt.Config{
// 		NewClaimsFunc: func(c echo.Context) jwt.Claims {
// 			return new(JwtCustomClaims)
// 		},
// 		SigningKey: []byte(jwtConfig.SecretKey),
// 	}
// }

// // GenerateToken generates a JWT token
// func (jwtConfig *JWTConfig) GenerateToken(userID int, userRole string) (string, error) {
// 	expire := jwt.NewNumericDate(time.Now().Local().Add(time.Hour * time.Duration(jwtConfig.ExpiresDuration)))

// 	claims := &JwtCustomClaims{
// 		ID:   userID,
// 		Role: userRole,
// 		RegisteredClaims: jwt.RegisteredClaims{
// 			ExpiresAt: expire,
// 		},
// 	}

// 	rawToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	token, err := rawToken.SignedString([]byte(jwtConfig.SecretKey))
// 	if err != nil {
// 		return "", err
// 	}
// 	return token, nil
// }

// // GetUser extracts user data from context
// func GetUser(c echo.Context) (*JwtCustomClaims, error) {
// 	user := c.Get("user").(*jwt.Token)
// 	if user == nil {
// 		return nil, errors.New("invalid token")
// 	}

// 	claims, ok := user.Claims.(*JwtCustomClaims)
// 	if !ok {
// 		return nil, errors.New("invalid token claims")
// 	}

// 	return claims, nil
// }

// // VerifyAdmin middleware to check if the user is an admin
// func VerifyAdmin(next echo.HandlerFunc) echo.HandlerFunc {
// 	return func(c echo.Context) error {
// 		userData, err := GetUser(c)
// 		if userData == nil || err != nil {
// 			return c.JSON(http.StatusUnauthorized, map[string]string{
// 				"message": "invalid token",
// 			})
// 		}

// 		if userData.Role != "admin" {
// 			return c.JSON(http.StatusUnauthorized, map[string]string{
// 				"message": "you are not an admin",
// 			})
// 		}

// 		return next(c)
// 	}
// }

// // VerifyUser middleware to verify the token and set user data in context
// func VerifyUser(next echo.HandlerFunc) echo.HandlerFunc {
// 	return func(c echo.Context) error {
// 		userData, err := GetUser(c)
// 		if userData == nil || err != nil {
// 			return c.JSON(http.StatusUnauthorized, map[string]string{
// 				"message": "invalid token",
// 			})
// 		}

// 		if userData.Role != "user" {
// 			return c.JSON(http.StatusUnauthorized, map[string]string{
// 				"message": "you are not an user",
// 			})
// 		}

// 		return next(c)
// 	}
// }

// // HashPassword hashes the password
// func hashPassword(password string) (string, error) {
// 	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// 	if err != nil {
// 		return "", err
// 	}
// 	return string(bytes), nil
// }

// // SeedDatabase seeds the database with admin and user data
// func SeedDatabase(db *sql.DB) {
// 	adminPasswordHash, err := hashPassword("admin123")
// 	if err != nil {
// 		log.Fatalf("Failed to hash admin password: %v", err)
// 	}

// 	userPasswordHash, err := hashPassword("user123")
// 	if err != nil {
// 		log.Fatalf("Failed to hash user password: %v", err)
// 	}

// 	// Create table if not exists
// 	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
//         id INT AUTO_INCREMENT PRIMARY KEY,
//         username VARCHAR(50) UNIQUE NOT NULL,
//         password VARCHAR(255) NOT NULL,
//         role VARCHAR(50) NOT NULL
//     )`)
// 	if err != nil {
// 		log.Fatalf("Failed to create table: %v", err)
// 	}

// 	// Insert admin and user
// 	_, err = db.Exec(`INSERT IGNORE INTO users (username, password, role) VALUES
//         ('admin', ?, 'admin'),
//         ('user', ?, 'user')`, adminPasswordHash, userPasswordHash)
// 	if err != nil {
// 		log.Fatalf("Failed to insert seed data: %v", err)
// 	}
// }

// // LoginRequest represents the JSON structure for login requests
// type LoginRequest struct {
// 	Username string `json:"username"`
// 	Password string `json:"password"`
// }

// // RegisterRequest represents the JSON structure for register requests
// type RegisterRequest struct {
// 	Username string `json:"username"`
// 	Password string `json:"password"`
// 	Role     string `json:"role"`
// }

// func main() {
// 	e := echo.New()

// 	// Connect to MySQL database
// 	dsn := "root:root123@tcp(127.0.0.1:3306)/rbac_example"
// 	db, err := sql.Open("mysql", dsn)
// 	if err != nil {
// 		log.Fatalf("Failed to connect to database: %v", err)
// 	}
// 	defer db.Close()

// 	// Seed the database with admin and user data
// 	SeedDatabase(db)

// 	// JWT configuration
// 	jwtConfig := &JWTConfig{
// 		SecretKey:       "your_secret_key",
// 		ExpiresDuration: 72, // Token expiration in hours
// 	}

// 	// Public endpoint to register a new user
// 	e.POST("/register", func(c echo.Context) error {
// 		var registerReq RegisterRequest
// 		if err := c.Bind(&registerReq); err != nil {
// 			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
// 		}

// 		username := registerReq.Username
// 		password := registerReq.Password
// 		role := registerReq.Role

// 		// Hash the password
// 		passwordHash, err := hashPassword(password)
// 		if err != nil {
// 			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to hash password"})
// 		}

// 		// Insert the new user into the database
// 		_, err = db.Exec(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, username, passwordHash, role)
// 		if err != nil {
// 			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to register user"})
// 		}

// 		return c.JSON(http.StatusOK, map[string]string{"message": "User registered successfully"})
// 	})

// 	// Public endpoint to login and generate token
// 	e.POST("/login", func(c echo.Context) error {
// 		var loginReq LoginRequest
// 		if err := c.Bind(&loginReq); err != nil {
// 			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
// 		}

// 		username := loginReq.Username
// 		password := loginReq.Password

// 		// Perform user authentication here (e.g., check username and password from database)
// 		var storedPasswordHash string
// 		var role string
// 		err := db.QueryRow("SELECT password, role FROM users WHERE username = ?", username).Scan(&storedPasswordHash, &role)
// 		if err != nil {
// 			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid credentials"})
// 		}

// 		// Verify password
// 		if err := bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(password)); err != nil {
// 			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid credentials"})
// 		}

// 		// Generate token
// 		userID := 1 // This should be fetched from the database
// 		token, err := jwtConfig.GenerateToken(userID, role)
// 		if err != nil {
// 			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Could not generate token"})
// 		}

// 		return c.JSON(http.StatusOK, map[string]string{"token": token})
// 	})

// 	// Group with JWT middleware
// 	r := e.Group("/restricted")
// 	r.Use(echojwt.WithConfig(jwtConfig.Init()))

// 	// Admin endpoint
// 	r.GET("/admin", VerifyAdmin(func(c echo.Context) error {
// 		return c.JSON(http.StatusOK, map[string]string{"message": "Welcome, admin!"})
// 	}))

// 	// User endpoint
// 	r.GET("/user", VerifyUser(func(c echo.Context) error {
// 		return c.JSON(http.StatusOK, map[string]string{"message": "Welcome, user!"})
// 	}))

// 	// Start the server
// 	e.Logger.Fatal(e.Start(":8080"))
// }
