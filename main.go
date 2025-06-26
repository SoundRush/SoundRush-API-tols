package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Конфигурация
const (
	SecretKey           = "your-secret-key"
	UploadDir           = "./uploads"
	AccessTokenDuration = 24 * time.Hour
)

// Модели
type User struct {
	ID       uint64 `gorm:"primaryKey"`
	Username string   `gorm:"unique;not null"`
	Email    string   `gorm:"unique;not null"`
	Password string `gorm:"not null"`
}

type Track struct {
	ID      uint64 `gorm:"id;primaryKey"`
	Title    string `gorm:"not null"`
	Artist   string `gorm:"artist;not null"`
	FilePath string `gorm:"not null"`
	UserID  uint64 `gorm:"not null"`
	User     User   `gorm:"foreignKey:UserID"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type TrackRequest struct {
	Title  string `form:"title" binding:"required"`
	Artist string `form:"artist" binding:"required"`
}

type Claims struct {
	UserID   uint64 `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Инициализация базы данных
func setupDB() (*gorm.DB, error) {
    dsn := ""
    var db *gorm.DB
    var err error

    for i := 0; i < 10; i++ {
        db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
        if err == nil {
            break
        }
        log.Printf("Failed to connect to database, retrying... (%d/10)", i+1)
        time.Sleep(3 * time.Second)
    }
    if err != nil {
        return nil, err
    }
    db.AutoMigrate(&User{}, &Track{})
    return db, nil
}


// Хелперы
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

func verifyPassword(password, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func generateJWT(user *User) (string, error) {
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(SecretKey))
}

// Middleware для авторизации
func authMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(SecretKey), nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		var user User
		if err := db.First(&user, claims.UserID).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}
		c.Set("user", user)
		c.Next()
	}
}

// Эндпоинты
func main() {
	// Инициализация
	if err := os.MkdirAll(UploadDir, 0755); err != nil {
		log.Fatal("Failed to create upload directory: ", err)
	}
	db, err := setupDB()
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}
	r := gin.Default()

	// Регистрация
	r.POST("/register", func(c *gin.Context) {
		var req RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var existingUser User
		if db.Where("email = ?", req.Email).First(&existingUser).Error == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email already exists"})
			return
		}
		hashedPassword, err := hashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		user := User{
			Username: req.Username,
			Email:    req.Email,
			Password: hashedPassword,
		}
		if err := db.Create(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
	})

	// Авторизация
	r.POST("/login", func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var user User
		if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}
		if err := verifyPassword(req.Password, user.Password); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}
		token, err := generateJWT(&user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"access_token": token, "token_type": "bearer"})
	})

	// Защищённые эндпоинты
	authorized := r.Group("/").Use(authMiddleware(db))

	// Загрузка трека
	authorized.POST("/tracks", func(c *gin.Context) {
		user, _ := c.Get("user")
		currentUser := user.(User)
		var req TrackRequest
		if err := c.ShouldBind(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "File required"})
			return
		}
		// Проверка формата файла (например, только mp3)
		if filepath.Ext(file.Filename) != ".mp3" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Only MP3 files are allowed"})
			return
		}

		filePath := fmt.Sprintf("%s/%d_%s", UploadDir, time.Now().UnixNano(), file.Filename)
		if err := c.SaveUploadedFile(file, filePath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
			return
		}

		track := Track{
			Title:    req.Title,
			Artist:   req.Artist,
			FilePath: filePath,
			UserID:   currentUser.ID,
		}
		if err := db.Create(&track).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save track"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Track uploaded successfully", "track_id": track.ID})
	})

	authorized.GET("/tracks", func(c *gin.Context) {
		var tracks []Track
		if err := db.Find(&tracks).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tracks"})
			return
		}
		c.JSON(http.StatusOK, tracks)
	})

	authorized.GET("/tracks/:id", func(c *gin.Context) {
		var track Track
		if err := db.First(&track, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Track not found"})
			return
		}
		c.JSON(http.StatusOK, track)
	})

	r.Run(":8080")
}
