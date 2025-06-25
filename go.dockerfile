# Используем официальный образ Go для сборки
FROM golang:1.24-alpine AS builder

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем go.mod и go.sum для кэширования зависимостей
COPY go.mod go.sum ./

# Загружаем зависимости
RUN go mod download

# Копируем исходный код
COPY *.go ./

# Собираем приложение
RUN CGO_ENABLED=0 GOOS=linux go build -o soundrush-api

# Финальный образ для запуска
FROM alpine:latest

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем бинарный файл из builder
COPY --from=builder /app/soundrush-api .

# Создаём директорию для загруженных треков
RUN mkdir -p /app/uploads

# Открываем порт 8080
EXPOSE 8080

# Команда для запуска приложения
CMD ["./soundrush-api"]