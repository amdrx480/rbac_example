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
	user := c.Get("user")
	if user == nil {
		log.Println("User not found in context")
		return nil, errors.New("invalid token")
	}

	token, ok := user.(*jwt.Token)
	if !ok {
		log.Printf("Expected *jwt.Token but got %T", user)
		return nil, errors.New("invalid token type")
	}

	claims, ok := token.Claims.(*JwtCustomClaims)
	if !ok {
		log.Println("Invalid token claims")
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

// CheckPermission checks if a user has a specific permission
func CheckPermission(userID int, permissionName string, db *sql.DB) (bool, error) {
	var username, roleName, permName string
	var roleID, permissionID int

	// Query to get user, role and permission details
	query := `
	SELECT u.username, r.name AS role_name, r.id AS role_id, p.name AS permission_name, p.id AS permission_id
	FROM users u
	JOIN roles r ON u.role = r.name
	JOIN role_permissions rp ON r.id = rp.role_id
	JOIN permissions p ON rp.permission_id = p.id
	WHERE u.id = ? AND p.name = ?
	`

	// Execute the query and scan the result
	row := db.QueryRow(query, userID, permissionName)
	err := row.Scan(&username, &roleName, &roleID, &permName, &permissionID)
	if err != nil {
		if err == sql.ErrNoRows {
			// If no rows are found, query user and role details separately
			// var role string
			var username string

			// Query to get the user and role details
			userQuery := `
			SELECT u.username, r.name AS role_name, r.id AS role_id
			FROM users u
			JOIN roles r ON u.role = r.name
			WHERE u.id = ?
			`
			err := db.QueryRow(userQuery, userID).Scan(&username, &roleName, &roleID)
			if err != nil {
				log.Printf("Error fetching user details: %v", err)
				return false, err
			}

			// Log user details without permission information
			log.Printf("User: %s, Role: %s (ID: %d), does not have the permission: %s", username, roleName, roleID, permissionName)
			return false, nil
		}
		// Log other errors
		log.Printf("Error executing query: %v", err)
		return false, err
	}

	// Log the details of the permission
	log.Printf("User: %s, Role: %s (ID: %d), has the permission: %s (ID: %d)", username, roleName, roleID, permName, permissionID)
	return true, nil
}

// VerifyPermission middleware to check if the user has the required permission
func VerifyPermission(requiredPermission string, db *sql.DB) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userData, err := GetUser(c)
			if userData == nil || err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"message": "invalid token",
				})
			}

			hasPermission, err := CheckPermission(userData.ID, requiredPermission, db)
			if err != nil || !hasPermission {
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

// SeedDatabase seeds the database with initial data
func SeedDatabase(db *sql.DB) {
	adminPasswordHash, err := hashPassword("faisal123")
	if err != nil {
		log.Fatalf("Failed to hash admin password: %v", err)
	}

	managerPasswordHash, err := hashPassword("fadly123")
	if err != nil {
		log.Fatalf("Failed to hash admin password: %v", err)
	}

	employeePasswordHash, err := hashPassword("fadli123")
	if err != nil {
		log.Fatalf("Failed to hash user password: %v", err)
	}

	// Create tables if not exists
	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL
    )
    `)
	if err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}

	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS permissions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) UNIQUE NOT NULL
    )
    `)
	if err != nil {
		log.Fatalf("Failed to create permissions table: %v", err)
	}

	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS roles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) UNIQUE NOT NULL
    )
    `)
	if err != nil {
		log.Fatalf("Failed to create roles table: %v", err)
	}

	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS role_permissions (
        role_id INT,
        permission_id INT,
        PRIMARY KEY (role_id, permission_id),
        FOREIGN KEY (role_id) REFERENCES roles(id),
        FOREIGN KEY (permission_id) REFERENCES permissions(id)
    )
    `)
	if err != nil {
		log.Fatalf("Failed to create role_permissions table: %v", err)
	}

	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS books (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        author VARCHAR(255) NOT NULL,
        published_year INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    `)
	if err != nil {
		log.Fatalf("Failed to create books table: %v", err)
	}

	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS user_books (
        user_id INT,
        book_id INT,
        PRIMARY KEY (user_id, book_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (book_id) REFERENCES books(id)
    )
    `)
	if err != nil {
		log.Fatalf("Failed to create user_books table: %v", err)
	}

	// Insert admin and user
	_, err = db.Exec(`
    INSERT INTO users (username, password, role) VALUES
        ('faisal', ?, 'admin'),
     	('fadly', ?, 'manager'),
        ('fadli', ?, 'employee')
    ON DUPLICATE KEY UPDATE password = VALUES(password), role = VALUES(role)
    `, adminPasswordHash, managerPasswordHash, employeePasswordHash)
	if err != nil {
		log.Fatalf("Failed to insert seed data: %v", err)
	}

	// Insert roles and permissions if needed
	_, err = db.Exec(`
    INSERT IGNORE INTO roles (name) VALUES ('admin'), ('manager'), ('employee');
    `)
	if err != nil {
		log.Fatalf("Failed to insert roles: %v", err)
	}

	_, err = db.Exec(`
    INSERT IGNORE INTO permissions (name) VALUES ('create_book'), ('read_book'), ('update_book'), ('delete_book');
    `)
	if err != nil {
		log.Fatalf("Failed to insert permissions: %v", err)
	}

	// Insert role_permissions while avoiding duplicates
	_, err = db.Exec(`
    INSERT IGNORE INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id
    FROM roles r
    JOIN permissions p ON p.name IN ('create_book', 'read_book', 'update_book', 'delete_book')
    WHERE r.name = 'admin' AND p.name IN ('create_book', 'read_book', 'update_book', 'delete_book')
    UNION
    SELECT r.id, p.id
    FROM roles r
    JOIN permissions p ON p.name IN ('read_book', 'update_book')
    WHERE r.name = 'manager' AND p.name IN ('read_book', 'update_book')
    UNION
    SELECT r.id, p.id
    FROM roles r
    JOIN permissions p ON p.name = 'read_book'
    WHERE r.name = 'employee' AND p.name = 'read_book';
    `)
	if err != nil {
		log.Fatalf("Failed to insert role and permission data: %v", err)
	}

	// Seed books data
	_, err = db.Exec(`
    INSERT IGNORE INTO books (title, author, published_year) VALUES
        ('Book One', 'Author A', 2020),
        ('Book Two', 'Author B', 2021);
    `)
	if err != nil {
		log.Fatalf("Failed to insert book data: %v", err)
	}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AddBookRequest represents the JSON structure for adding a new book
type AddBookRequest struct {
	Title         string `json:"title"`
	Author        string `json:"author"`
	PublishedYear int    `json:"published_year"`
}

// UpdateBookRequest represents the JSON structure for updating a book
type UpdateBookRequest struct {
	Title         string `json:"title"`
	Author        string `json:"author"`
	PublishedYear int    `json:"published_year"`
}

func main() {

	e := echo.New()
	dsn := "root:root123@tcp(127.0.0.1:3306)/rbac_example"
	db, err := sql.Open("mysql", dsn)
	// db, err := sql.Open("mysql", "root:root123@tcp(127.0.0.1:3306)/rbac_example")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	SeedDatabase(db)

	jwtConfig := &JWTConfig{
		SecretKey:       "your-secret-key",
		ExpiresDuration: 24, // Token expires in 24 hours
	}

	// Public endpoint to login and generate token
	e.POST("/login", func(c echo.Context) error {
		var loginReq LoginRequest
		if err := c.Bind(&loginReq); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
		}

		username := loginReq.Username
		password := loginReq.Password

		// Perform user authentication here
		var storedPasswordHash string
		var role string
		var userID int

		// Query to get the stored password hash and role
		err := db.QueryRow("SELECT id, password, role FROM users WHERE username = ?", username).Scan(&userID, &storedPasswordHash, &role)
		if err != nil {
			// Return unauthorized if user is not found or any other error occurs
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid credentials"})
		}

		// Verify password
		if err := bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(password)); err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid credentials"})
		}

		// Generate token
		token, err := jwtConfig.GenerateToken(userID, role)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Could not generate token"})
		}

		return c.JSON(http.StatusOK, map[string]string{"token": token})
	})

	e.POST("/register", func(c echo.Context) error {
		var registerData struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"` // Example: 'admin', 'manager', 'employee'
		}

		// Bind JSON data to the struct
		if err := c.Bind(&registerData); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid input"})
		}

		// Hash password
		hashedPassword, err := hashPassword(registerData.Password)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Could not hash password"})
		}

		// Insert user into database
		_, err = db.Exec(`
			INSERT INTO users (username, password, role)
			VALUES (?, ?, ?)
		`, registerData.Username, hashedPassword, registerData.Role)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Could not register user"})
		}

		return c.JSON(http.StatusOK, map[string]string{"message": "User registered successfully"})
	})

	// Group with JWT middleware
	r := e.Group("/restricted")
	r.Use(echojwt.WithConfig(jwtConfig.Init()))

	// Admin endpoint with permission check
	// r.GET("/admin", VerifyPermission("view_admin", db)(func(c echo.Context) error {
	r.GET("/admin", VerifyPermission("read_book", db)(func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "Welcome, admin!"})
	}))

	// User endpoint with permission check
	r.GET("/user", VerifyPermission("view_user", db)(func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "Welcome, user!"})
	}))

	// Middleware testing
	r.GET("/test_permission", VerifyPermission("create_book", db)(func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "Permission granted!"})
	}))

	// Endpoint untuk menambahkan buku
	r.POST("/books", VerifyPermission("create_book", db)(func(c echo.Context) error {
		var req AddBookRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
		}

		_, err := db.Exec(`INSERT INTO books (title, author, published_year) VALUES (?, ?, ?)`,
			req.Title, req.Author, req.PublishedYear)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to add book"})
		}

		return c.JSON(http.StatusOK, map[string]string{"message": "Book added successfully"})
	}))

	// Endpoint untuk mendapatkan daftar buku
	r.GET("/books", VerifyPermission("read_book", db)(func(c echo.Context) error {
		rows, err := db.Query(`SELECT id, title, author, published_year FROM books`)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch books"})
		}
		defer rows.Close()

		var books []map[string]interface{}
		for rows.Next() {
			var id, publishedYear int
			var title, author string
			if err := rows.Scan(&id, &title, &author, &publishedYear); err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to scan book"})
			}
			books = append(books, map[string]interface{}{
				"id":             id,
				"title":          title,
				"author":         author,
				"published_year": publishedYear,
			})
		}

		return c.JSON(http.StatusOK, books)
	}))

	// Endpoint untuk memperbarui buku
	r.PUT("/books/:id", VerifyPermission("update_book", db)(func(c echo.Context) error {
		id := c.Param("id")
		var req UpdateBookRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
		}

		_, err := db.Exec(`UPDATE books SET title = ?, author = ?, published_year = ? WHERE id = ?`,
			req.Title, req.Author, req.PublishedYear, id)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update book"})
		}

		return c.JSON(http.StatusOK, map[string]string{"message": "Book updated successfully"})
	}))

	// Endpoint untuk menghapus buku
	r.DELETE("/books/:id", VerifyPermission("delete_book", db)(func(c echo.Context) error {
		id := c.Param("id")
		_, err := db.Exec(`DELETE FROM books WHERE id = ?`, id)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to delete book"})
		}

		return c.JSON(http.StatusOK, map[string]string{"message": "Book deleted successfully"})
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
