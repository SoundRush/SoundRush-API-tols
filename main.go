package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
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
	Username string `gorm:"unique;not null"`
	Email    string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
}

type Track struct {
	ID       uint64 `gorm:"id;primaryKey"`
	Title    string `gorm:"not null"`
	Artist   string `gorm:"artist;not null"`
	FilePath string `gorm:"not null"`
	UserID   uint64 `gorm:"not null"`
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

// Расширенная структура для конфигурации микросервисов
// config.json пример:
//
//	{
//	  "services": [
//	    {
//	      "name": "auth",
//	      "ip": "127.0.0.1",
//	      "port": 8080,
//	      "health_check": "/health",
//	      "start_cmd": "docker-compose up -d auth"
//	    }
//	  ]
//	}
type ServiceConfig struct {
	Name        string `json:"name"`
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	HealthCheck string `json:"health_check"`
	StartCmd    string `json:"start_cmd"`
}

type Config struct {
	Services []ServiceConfig `json:"services"`
}

// Функция для чтения конфигурации из JSON
func loadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
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

func checkServiceHealth(svc ServiceConfig) bool {
	url := fmt.Sprintf("http://%s:%d%s", svc.IP, svc.Port, svc.HealthCheck)
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func tryStartService(svc ServiceConfig) {
	if svc.StartCmd == "" {
		log.Printf("Нет команды запуска для сервиса %s", svc.Name)
		return
	}
	log.Printf("Пытаюсь поднять сервис %s: %s", svc.Name, svc.StartCmd)
	// Запуск команды старта сервиса
	go func() {
		cmd := exec.Command("sh", "-c", svc.StartCmd)
		if err := cmd.Run(); err != nil {
			log.Printf("Ошибка запуска сервиса %s: %v", svc.Name, err)
		}
	}()
}

// Эндпоинты
func main() {
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatal("Failed to load config: ", err)
	}
	fmt.Println("Загружена конфигурация сервисов:", config)

	// Балансировщик нагрузки и мониторинг сервисов
	for _, svc := range config.Services {
		fmt.Printf("Микросервис: %s, адрес: %s:%d\n", svc.Name, svc.IP, svc.Port)
	}

	// Запуск мониторинга сервисов в отдельной горутине
	go func() {
		for {
			for _, svc := range config.Services {
				if !checkServiceHealth(svc) {
					log.Printf("Сервис %s не отвечает. Пытаюсь поднять...", svc.Name)
					tryStartService(svc)
				} else {
					log.Printf("Сервис %s работает нормально", svc.Name)
				}
			}
			time.Sleep(5 * time.Second)
		}
	}()

	// Бесконечный цикл, чтобы API не завершался
	select {}
}
